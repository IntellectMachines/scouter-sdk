"""
Scouter Backend HTTP Client.

Provides typed methods to communicate with the Scouter backend API.
Used by ScouterClient when ``backend_url`` is configured.
Falls back gracefully — returns None on connection errors so the
SDK can fall back to local evaluation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger("scouter.backend")


def _enc(value: str) -> str:
    """Encode a value safely for inclusion in a URL path segment."""
    return quote(str(value), safe="")


class CapabilityEscalationError(Exception):
    """Raised when a credential mint is blocked by aggregate scope ceiling or dangerous capability combination."""

    def __init__(self, detail: dict):
        self.detail = detail
        super().__init__(detail.get("reason", "Capability escalation"))


class BackendClient:
    """HTTP client for the Scouter backend REST API."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 5.0,
        api_key: Optional[str] = None,
        client: Optional[Any] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        headers = {}
        if api_key:
            headers["X-Scouter-API-Key"] = api_key
        self._client = client or httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers=headers,
            limits=httpx.Limits(
                max_keepalive_connections=10,
                max_connections=20,
                keepalive_expiry=30,
            ),
        )

    def _request(self, method: str, path: str, *, caller: str = "", **kwargs) -> Optional[dict]:
        """Unified request handler with proper error logging."""
        try:
            r = self._client.request(method, path, **kwargs)
            r.raise_for_status()
            return r.json()
        except httpx.TimeoutException:
            logger.warning("Scouter backend timeout on %s %s (%s)", method, path, caller)
            return None
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 409:
                # Capability escalation — surface to caller instead of swallowing
                try:
                    detail = e.response.json()
                except Exception:
                    detail = {"reason": e.response.text}
                raise CapabilityEscalationError(detail)
            if status == 401 or status == 403:
                logger.error("Scouter backend auth failed (%d) on %s %s — check API key", status, method, path)
            elif status >= 500:
                logger.warning("Scouter backend error (%d) on %s %s (%s)", status, method, path, caller)
            else:
                logger.debug("Scouter backend %d on %s %s (%s)", status, method, path, caller)
            return None
        except httpx.HTTPError as e:
            logger.warning("Scouter backend connection error on %s %s: %s", method, path, e)
            return None

    # ── Intent Registry ────────────────────────────────────────────

    def register_intent(
        self,
        agent_id: str,
        natural_language: str,
        permitted_actions: List[str],
        excluded_actions: List[str],
        principal_chain: Optional[List[dict]] = None,
        version: str = "1.0",
    ) -> Optional[dict]:
        return self._request("POST", "/api/v1/intents", caller="register_intent", json={
            "agent_id": agent_id,
            "natural_language": natural_language,
            "permitted_actions": permitted_actions,
            "excluded_actions": excluded_actions,
            "principal_chain": principal_chain or [],
            "version": version,
        })

    def get_intent(self, intent_id: str) -> Optional[dict]:
        return self._request("GET", f"/api/v1/intents/{_enc(intent_id)}", caller="get_intent")

    # ── Consequence Engine ─────────────────────────────────────────

    def evaluate(
        self,
        action: Dict[str, Any],
        intent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Optional[dict]:
        return self._request("POST", "/api/v1/engine/evaluate", caller="evaluate", json={
            "action": action,
            "intent_id": intent_id,
            "trace_id": trace_id,
            "model": model,
        })

    # ── Observability ──────────────────────────────────────────────

    def ingest_span(
        self,
        trace_id: str,
        span_type: str,
        data: dict,
        agent_id: str = "",
        intent_id: str = "",
    ) -> Optional[dict]:
        return self._request("POST", "/api/v1/observability/traces", caller="ingest_span", json={
            "trace_id": trace_id,
            "span_type": span_type,
            "data": data,
            "agent_id": agent_id,
            "intent_id": intent_id,
        })

    def analyze_trace(self, trace_id: str) -> Optional[dict]:
        return self._request("POST", f"/api/v1/observability/traces/{_enc(trace_id)}/analyze", caller="analyze_trace")

    # ── Audit ──────────────────────────────────────────────────────

    def verify_artifact(self, artifact_id: str) -> Optional[dict]:
        return self._request("GET", f"/api/v1/audit/verify/{_enc(artifact_id)}", caller="verify_artifact")

    def export_compliance(self) -> Optional[dict]:
        return self._request("GET", "/api/v1/audit/export", caller="export_compliance")

    # ── Health ─────────────────────────────────────────────────────

    def health(self) -> bool:
        try:
            r = self._client.get("/health")
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    # ── Telemetry ──────────────────────────────────────────────────

    def get_telemetry_stats(self) -> Optional[dict]:
        """Get system-wide telemetry statistics."""
        return self._request("GET", "/api/v1/telemetry/stats", caller="get_telemetry_stats")

    def get_agent_telemetry(
        self, agent_id: str, limit: int = 100
    ) -> Optional[List[dict]]:
        """Get telemetry records for a specific agent."""
        return self._request("GET", f"/api/v1/telemetry/agent/{_enc(agent_id)}", caller="get_agent_telemetry", params={"limit": limit})

    def get_agent_stats(self, agent_id: str) -> Optional[dict]:
        """Get aggregated statistics for an agent."""
        return self._request("GET", f"/api/v1/telemetry/agent/{_enc(agent_id)}/stats", caller="get_agent_stats")

    def get_trace_telemetry(self, trace_id: str) -> Optional[List[dict]]:
        """Get telemetry records for a specific trace."""
        return self._request("GET", f"/api/v1/telemetry/trace/{_enc(trace_id)}", caller="get_trace_telemetry")

    # ── Prompt Analyzer ────────────────────────────────────────────

    def analyze_prompt(
        self,
        prompt: str,
        intent_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Optional[dict]:
        """Analyze a prompt for intent, risk, impact, and get an ALLOWED/REJECTED decision."""
        return self._request("POST", "/api/v1/prompt/analyze", caller="analyze_prompt", json={
            "prompt": prompt,
            "intent_id": intent_id,
            "agent_id": agent_id,
        }, timeout=120.0)

    def analyze_prompt_batch(
        self,
        prompts: List[str],
        intent_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Optional[dict]:
        """Analyze multiple prompts in a single request."""
        return self._request("POST", "/api/v1/prompt/analyze/batch", caller="analyze_prompt_batch", json={
            "prompts": prompts,
            "intent_id": intent_id,
            "agent_id": agent_id,
        }, timeout=300.0)

    # ── JIT Credentials ────────────────────────────────────────────

    def mint_credential(
        self,
        intent_id: str,
        artifact_id: str,
        scope: Optional[dict] = None,
        ttl_seconds: Optional[int] = None,
        task_id: Optional[str] = None,
    ) -> Optional[dict]:
        """Mint a JIT credential after a PASS_THROUGH decision."""
        body: Dict[str, Any] = {
            "intent_id": intent_id,
            "artifact_id": artifact_id,
            "scope": scope or {},
        }
        if ttl_seconds:
            body["ttl_seconds"] = ttl_seconds
        if task_id:
            body["task_id"] = task_id
        return self._request("POST", "/api/v1/auth/credentials/mint", caller="mint_credential", json=body)

    # ── Task Lifecycle (Change 2) ──────────────────────────────────

    def open_task(
        self,
        intent_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        description: Optional[str] = None,
        parent_task_id: Optional[str] = None,
    ) -> Optional[dict]:
        """Open a task. Bind credentials minted within it to its task_id."""
        return self._request(
            "POST", "/api/v1/auth/tasks/open", caller="open_task",
            json={
                "intent_id": intent_id,
                "agent_id": agent_id,
                "description": description,
                "parent_task_id": parent_task_id,
            },
        )

    def close_task(self, task_id: str, terminal_event: str = "completed") -> Optional[dict]:
        """Close a task — cascades revocation to every bound credential."""
        return self._request(
            "POST", "/api/v1/auth/tasks/close", caller="close_task",
            json={"task_id": task_id, "terminal_event": terminal_event},
        )

    def checkpoint_task(self, task_id: str) -> Optional[dict]:
        """Heartbeat for long-running tasks. Resets staleness timer."""
        return self._request(
            "POST", "/api/v1/auth/tasks/checkpoint", caller="checkpoint_task",
            json={"task_id": task_id},
        )

    def get_task(self, task_id: str) -> Optional[dict]:
        return self._request("GET", f"/api/v1/auth/tasks/{_enc(task_id)}", caller="get_task")

    def revoke_credential(
        self,
        credential_id: str,
        reason: str = "task_complete",
    ) -> Optional[dict]:
        """Revoke a JIT credential."""
        return self._request("POST", "/api/v1/auth/credentials/revoke", caller="revoke_credential", json={
            "credential_id": credential_id, "reason": reason,
        })

    def validate_credential(self, token: str) -> Optional[dict]:
        """Validate a JIT credential token."""
        return self._request("POST", "/api/v1/auth/credentials/validate", caller="validate_credential", json={
            "token": token,
        })

    # ── PBAC Policies ──────────────────────────────────────────────

    def evaluate_pbac(
        self,
        intent_id: str,
        action_type: str,
        target_system: str = "",
    ) -> Optional[dict]:
        """Check PBAC policy for an action."""
        return self._request("POST", "/api/v1/auth/policies/evaluate", caller="evaluate_pbac", json={
            "intent_id": intent_id,
            "action_type": action_type,
            "target_system": target_system,
        })

    def list_policies(self, intent_id: Optional[str] = None) -> Optional[List[dict]]:
        """List PBAC policies."""
        params = {}
        if intent_id:
            params["intent_id"] = intent_id
        return self._request("GET", "/api/v1/auth/policies", caller="list_policies", params=params)

    # ── Agent DID Registry ─────────────────────────────────────────

    def register_agent_did(
        self, agent_id: str, display_name: Optional[str] = None
    ) -> Optional[dict]:
        """Register a DID for an agent. Returns DID Document + private key."""
        return self._request("POST", "/api/v1/dids/register", caller="register_agent_did", json={
            "agent_id": agent_id,
            "display_name": display_name,
        })

    def resolve_did(self, did: str) -> Optional[dict]:
        """Resolve a DID Document by DID string."""
        return self._request("GET", f"/api/v1/dids/{_enc(did)}", caller="resolve_did")

    def revoke_did(self, did: str, reason: str = "cessation") -> Optional[dict]:
        """Revoke a DID. Invalidates associated JIT credentials."""
        return self._request("POST", f"/api/v1/dids/{_enc(did)}/revoke", caller="revoke_did", json={
            "reason": reason,
        })

    def rotate_did_key(self, did: str) -> Optional[dict]:
        """Rotate the Ed25519 keypair for a DID."""
        return self._request("POST", f"/api/v1/dids/{_enc(did)}/keys/rotate", caller="rotate_did_key")
