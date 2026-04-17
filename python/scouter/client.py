"""
ScouterClient -- Main SDK entry point.

Provides the Intent Registry, Consequence Engine, Action Triage Classifier,
Execution Interceptor, and JIT credential lifecycle.

Operates in two modes:
  - **Local** (default): Everything runs in-process.
  - **Connected** (backend_url set): Routes to the Scouter backend
    for persistent storage, Ed25519 signing, and behavioral analysis.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from scouter.api.backend import CapabilityEscalationError
from scouter.engine.intent import IntentRegistry
from scouter.engine.consequence import ConsequenceEngine
from scouter.console.logger import ConsoleLogger
from scouter.classifier.action_triage import ActionTriageClassifier


class ScouterClient:
    """
    Primary Scouter SDK handle.

    Args:
        api_key:      Scouter API key (used for backend auth).
        mode:         "audit" (default) -- non-blocking, log-only.
        verbose:      Enable rich CLI console output.
        backend_url:  URL of the Scouter backend (e.g. http://localhost:8000).
                      When set, the SDK routes evaluations to the backend.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        mode: str = "audit",
        verbose: bool = True,
        backend_url: Optional[str] = None,
    ) -> None:
        self.api_key = api_key
        self.mode = mode
        self.trace_id = f"trace-{uuid.uuid4().hex[:12]}"

        # Local engine (always available as fallback)
        self.registry = IntentRegistry()
        self.engine = ConsequenceEngine(mode=mode)
        self.console = ConsoleLogger(verbose=verbose)

        # Action Triage Classifier -- decides what needs backend evaluation
        self.classifier = ActionTriageClassifier()

        # Execution Interceptor -- guards for shell/DB/API actions
        self.interceptor = None

        # JIT credential lifecycle
        self._active_credentials: Dict[str, dict] = {}

        # Backend client (optional)
        self.backend = None
        self.backend_url = backend_url
        if backend_url:
            from scouter.api.backend import BackendClient
            self.backend = BackendClient(backend_url, api_key=api_key)
            if self.backend.health():
                self.console.log_info("init", f"Connected to backend at {backend_url}")
                # Initialize hybrid execution interceptor with server support
                from scouter.guards.execution_interceptor import ExecutionInterceptor
                self.interceptor = ExecutionInterceptor(
                    mode="hybrid",
                    backend_url=backend_url,
                    verbose=verbose,
                )
            else:
                self.console.log_info("init", f"Backend at {backend_url} unreachable -- using local engine")
                self.backend = None

        # If no backend, use local enforce-mode interceptor
        if not self.interceptor:
            from scouter.guards.execution_interceptor import ExecutionInterceptor
            self.interceptor = ExecutionInterceptor(
                mode="audit" if mode == "audit" else "enforce",
                verbose=verbose,
            )

        self.console.log_info("init", f"Scouter client initialised  mode={mode}")

    def new_trace(self) -> str:
        """Start a new trace and return the trace_id."""
        self.trace_id = f"trace-{uuid.uuid4().hex[:12]}"
        return self.trace_id

    # ── JIT Credential Lifecycle ───────────────────────────────────────

    def get_credential(self, action_type: str) -> Optional[str]:
        """Get the JIT token for a given action type."""
        cred = self._active_credentials.get(action_type)
        if cred:
            return cred.get("token")
        return None

    def revoke_all_credentials(self, reason: str = "task_complete") -> None:
        """Revoke all active JIT credentials via the backend."""
        if not self.backend:
            self._active_credentials.clear()
            return
        for action_type, cred in list(self._active_credentials.items()):
            cred_id = cred.get("credential_id")
            if cred_id:
                self.backend.revoke_credential(cred_id, reason)
        self._active_credentials.clear()

    # ── Task Lifecycle (Change 2) ──────────────────────────────────────

    def task(
        self,
        intent_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        description: Optional[str] = None,
        parent_task_id: Optional[str] = None,
    ) -> "_TaskContext":
        """
        Open a task that scopes credentials to its lifetime.

        Use as a context manager:

            with client.task(intent_id="...", agent_id="bot") as t:
                client.backend.mint_credential(..., task_id=t.task_id)
                ... do work ...
            # on exit: every credential bound to t.task_id is auto-revoked

        Falls back to a no-op context if no backend is configured.
        """
        return _TaskContext(
            client=self,
            intent_id=intent_id,
            agent_id=agent_id,
            description=description,
            parent_task_id=parent_task_id,
        )


class _TaskContext:
    """Context manager that opens/closes a Scouter task."""

    def __init__(
        self,
        client: "ScouterClient",
        intent_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        description: Optional[str] = None,
        parent_task_id: Optional[str] = None,
    ) -> None:
        self._client = client
        self._intent_id = intent_id
        self._agent_id = agent_id
        self._description = description
        self._parent_task_id = parent_task_id
        self.task_id: Optional[str] = None

    def __enter__(self) -> "_TaskContext":
        if self._client.backend:
            result = self._client.backend.open_task(
                intent_id=self._intent_id,
                agent_id=self._agent_id,
                description=self._description,
                parent_task_id=self._parent_task_id,
            )
            if result and result.get("task_id"):
                self.task_id = result["task_id"]
                self._client.console.log_info("task", f"opened {self.task_id}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client.backend and self.task_id:
            terminal = "failed" if exc_type else "completed"
            try:
                self._client.backend.close_task(self.task_id, terminal_event=terminal)
                self._client.console.log_info("task", f"closed {self.task_id} ({terminal})")
            except Exception as e:  # noqa: BLE001
                self._client.console.log_info("task", f"close failed: {e}")

    def checkpoint(self) -> None:
        """Reset the staleness timer (for long-running tasks)."""
        if self._client.backend and self.task_id:
            self._client.backend.checkpoint_task(self.task_id)
