"""
ServerGuard — HTTP client that sends suspicious actions to the backend
for full validation through all 3 security layers.

This is the "heavy" path — only called when the LightGuard flags an
action as suspicious (~1% of all actions).

The backend runs:
  1. Full regex rule engine (60+ patterns across shell/database/api)
  2. Prompt analysis via HuggingFace models (optional)
  3. Consequence scoring

The client gets back a definitive BLOCK / WARN / ALLOW decision.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import httpx

from scouter.guards.base import GuardDecision, GuardResult


class ServerGuard:
    """
    Sends suspicious actions to the backend for full server-side validation.

    Usage:
        sg = ServerGuard(backend_url="http://127.0.0.1:8000")
        result = sg.validate("shell", "rm -rf /")
        # result is a GuardResult with BLOCK/WARN/ALLOW from the server
    """

    def __init__(
        self,
        backend_url: str = "http://127.0.0.1:8000",
        timeout: float = 5.0,
        agent_id: Optional[str] = None,
    ):
        self.backend_url = backend_url.rstrip("/")
        self.agent_id = agent_id
        self._timeout = timeout
        self._client = httpx.Client(
            base_url=self.backend_url,
            timeout=timeout,
            limits=httpx.Limits(
                max_keepalive_connections=5,
                max_connections=10,
                keepalive_expiry=30,
            ),
        )

        # Stats
        self.server_calls = 0
        self.server_blocks = 0
        self.server_warns = 0
        self.server_allows = 0
        self.server_errors = 0
        self.total_latency_ms = 0.0

    def validate(
        self,
        guard_type: str,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardResult:
        """
        Send an action to the backend for full validation.

        Args:
            guard_type: "shell", "database", or "api"
            action: The command / query / request to validate
            context: Optional extra context

        Returns:
            GuardResult with the server's decision.
            On server error, returns a WARN result (fail-open for usability,
            but the caller can choose fail-closed behavior).
        """
        t0 = time.monotonic()
        self.server_calls += 1

        try:
            r = self._client.post(
                "/api/v1/guards/validate",
                json={
                    "guard_type": guard_type,
                    "action": action,
                    "agent_id": self.agent_id,
                    "context": context or {},
                },
            )
            r.raise_for_status()
            data = r.json()

            elapsed_ms = (time.monotonic() - t0) * 1000
            self.total_latency_ms += elapsed_ms

            decision_str = data.get("decision", "ALLOW").upper()
            decision = GuardDecision(decision_str) if decision_str in ("BLOCK", "WARN", "ALLOW") else GuardDecision.WARN

            if decision == GuardDecision.BLOCK:
                self.server_blocks += 1
            elif decision == GuardDecision.WARN:
                self.server_warns += 1
            else:
                self.server_allows += 1

            return GuardResult(
                decision=decision,
                guard_type=guard_type,
                action=action,
                reason=data.get("reason", "Server validation"),
                risk_score=data.get("risk_score", 0.0),
                matched_rules=data.get("matched_rules", []),
            )

        except Exception as e:
            elapsed_ms = (time.monotonic() - t0) * 1000
            self.total_latency_ms += elapsed_ms
            self.server_errors += 1

            # Server unreachable — return fallback result
            return GuardResult(
                decision=GuardDecision.WARN,
                guard_type=guard_type,
                action=action,
                reason=f"Server unreachable ({type(e).__name__}): falling back to WARN",
                risk_score=50.0,
                matched_rules=["server_unreachable"],
            )

    def validate_shell(self, command: str) -> GuardResult:
        return self.validate("shell", command)

    def validate_sql(self, query: str) -> GuardResult:
        return self.validate("database", query)

    def validate_api(self, request: str) -> GuardResult:
        return self.validate("api", request)

    def report(self, result: GuardResult) -> bool:
        """
        Report a guard decision to the backend for audit.
        Best-effort — returns False on failure, never raises.
        """
        try:
            self._client.post(
                "/api/v1/guards/report",
                json={
                    "guard_type": result.guard_type,
                    "decision": result.decision.value,
                    "rule_id": result.matched_rules[0] if result.matched_rules else "none",
                    "severity": "CRITICAL" if result.risk_score >= 80 else "HIGH" if result.risk_score >= 60 else "MEDIUM" if result.risk_score >= 40 else "LOW",
                    "message": result.reason,
                    "action": result.action[:2000],
                    "agent_id": self.agent_id,
                },
            )
            return True
        except Exception:
            return False

    @property
    def avg_latency_ms(self) -> float:
        return (self.total_latency_ms / self.server_calls) if self.server_calls else 0.0

    @property
    def stats(self) -> dict:
        return {
            "server_calls": self.server_calls,
            "server_blocks": self.server_blocks,
            "server_warns": self.server_warns,
            "server_allows": self.server_allows,
            "server_errors": self.server_errors,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
        }

    def close(self):
        self._client.close()
