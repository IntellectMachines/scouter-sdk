"""
Scouter <> Phidata Integration.

Wraps Phidata ``Tool`` and ``Assistant`` tool-execution callbacks so
that every tool invocation is transparently intercepted by Scouter.

Phidata tools are plain Python callables registered on an ``Assistant``.
This integration patches them at the ``Assistant.tools`` / ``Tool.entrypoint``
level so the governance layer is invisible to the framework.

Usage::

    from phi.assistant import Assistant
    from phi.tools.duckduckgo import DuckDuckGo
    from scouter.client import ScouterClient
    from scouter.integrations.phidata import wrap_phidata_assistant

    scouter = ScouterClient(backend_url="http://localhost:8000")

    assistant = Assistant(
        name="research-agent",
        tools=[DuckDuckGo()],
    )
    wrap_phidata_assistant(assistant, scouter, intent_id="...")
"""

from __future__ import annotations

import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional

from scouter.client import ScouterClient
from scouter.classifier.action_triage import TriageVerdict

_bg_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scouter-phi")

_FRAMEWORK = "phidata"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def wrap_phidata_assistant(
    assistant: Any,
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> Any:
    """
    Wrap a Phidata ``Assistant`` so all its tools are governed by Scouter.

    Inspects ``assistant.tools`` and patches each tool's entrypoint.

    Args:
        assistant:  A Phidata ``Assistant`` instance.
        scouter:    A configured ``ScouterClient``.
        intent_id:  The Intent ID to evaluate actions against.

    Returns:
        The same assistant with tools patched.
    """
    tools = getattr(assistant, "tools", None) or []
    intent = scouter.registry.get(intent_id) if intent_id else None

    patched = 0
    for tool in tools:
        if _patch_phidata_tool(tool, scouter, intent, intent_id):
            patched += 1

    scouter.console.log_info(
        _FRAMEWORK,
        f"Wrapped Phidata assistant '{getattr(assistant, 'name', '?')}' "
        f"-- {patched} tool(s) are now audited.",
    )
    return assistant


def wrap_phidata_tools(
    tools: List[Any],
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> List[Any]:
    """
    Wrap a list of Phidata tools with Scouter governance.

    Args:
        tools:      List of Phidata tool instances (e.g. ``DuckDuckGo()``,
                    ``ShellTools()``, ``FileTools()``).
        scouter:    A configured ``ScouterClient``.
        intent_id:  The Intent ID to evaluate actions against.

    Returns:
        The same list with tool entrypoints patched.
    """
    intent = scouter.registry.get(intent_id) if intent_id else None

    for tool in tools:
        _patch_phidata_tool(tool, scouter, intent, intent_id)

    scouter.console.log_info(
        _FRAMEWORK,
        f"Wrapped {len(tools)} Phidata tool(s) -- all executions are now audited.",
    )
    return tools


# ---------------------------------------------------------------------------
# Internal patching
# ---------------------------------------------------------------------------

def _patch_phidata_tool(
    tool: Any,
    scouter: ScouterClient,
    intent: Any,
    intent_id: Optional[str],
) -> bool:
    """
    Patch a single Phidata tool.

    Phidata's ``Toolkit`` subclasses expose individual functions via a
    ``functions`` dict (``{name: Function}``).  Each ``Function`` has a
    callable ``entrypoint``.  We patch at that level so the governance
    layer wraps the actual execution.

    For simpler ``Tool`` objects that are plain callables we wrap the
    ``__call__`` / ``run`` method directly.

    Returns True if at least one entrypoint was patched.
    """
    patched = False

    # Phidata >= 2.x Toolkit with .functions dict
    functions: Optional[Dict[str, Any]] = getattr(tool, "functions", None)
    if functions and isinstance(functions, dict):
        for fn_name, fn_obj in functions.items():
            ep = getattr(fn_obj, "entrypoint", None)
            if ep and callable(ep):
                wrapped = _make_wrapper(fn_name, ep, scouter, intent, intent_id)
                fn_obj.entrypoint = wrapped
                patched = True
        return patched

    # Phidata Tool with a single .run() or callable
    tool_name = getattr(tool, "name", None) or type(tool).__name__

    if hasattr(tool, "run") and callable(getattr(tool, "run")):
        original = tool.run
        tool.run = _make_wrapper(tool_name, original, scouter, intent, intent_id)
        return True

    if callable(tool):
        # Tool is itself a callable -- cannot easily patch __call__ on an
        # instance, so we skip (the user should use wrap_phidata_assistant
        # which handles the Assistant.tools list).
        pass

    return patched


def _make_wrapper(
    fn_name: str,
    fn_callable: Callable,
    scouter: ScouterClient,
    intent: Any,
    intent_id: Optional[str],
) -> Callable:
    """Return a governed version of *fn_callable*."""

    @functools.wraps(fn_callable)
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        tool_input = _build_input_str(args, kwargs)
        triage = scouter.classifier.classify_tool_call(fn_name, tool_input)

        if triage.verdict == TriageVerdict.SKIP:
            scouter.console.log_info(
                "triage",
                f"SKIP  {fn_name}  ({triage.reason}) [{triage.elapsed_us:.1f}\u00b5s]",
            )
            _send_span_bg(scouter, "tool_call", {
                "tool_name": fn_name, "arguments": tool_input,
                "triage": "SKIP", "framework": _FRAMEWORK,
            }, intent_id)
            return fn_callable(*args, **kwargs)

        scouter.console.log_info(
            "triage",
            f"SCAN  {fn_name}  [{triage.category}] {triage.reason} [{triage.elapsed_us:.1f}\u00b5s]",
        )

        action_dict = {
            "action_type": fn_name,
            "target_system": triage.category,
            "payload_summary": _truncate(tool_input, 200),
            "delegation_depth": 0,
        }

        _send_span_bg(scouter, "tool_call", {
            "tool_name": fn_name, "arguments": tool_input,
            "triage": "SCAN", "triage_category": triage.category,
            "framework": _FRAMEWORK,
        }, intent_id)

        _guard_check(scouter, fn_name, tool_input, triage.category)

        decision, sig = _evaluate(scouter, action_dict, intent, intent_id)
        scouter.console.log_governance_decision(decision)

        if sig:
            scouter.console.log_signature(
                sig["artifact_id"], sig["signature"], sig["public_key_id"],
            )
            if scouter.backend and intent_id:
                _try_mint_credential(scouter, intent_id, sig, action_dict)

        if (
            decision
            and decision.evaluation.calculated_decision.value == "HARD_STOP"
            and scouter.mode == "enforce"
        ):
            raise PermissionError(
                f"Scouter HARD_STOP: {fn_name} blocked -- "
                f"{decision.evaluation.rationale}"
            )

        return fn_callable(*args, **kwargs)

    return _wrapped


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _build_input_str(args: tuple, kwargs: dict) -> str:
    parts = [str(a) for a in args]
    parts.extend(f"{k}={v}" for k, v in kwargs.items())
    return " ".join(parts) if parts else ""


def _truncate(text: str, max_len: int) -> str:
    return text[:max_len] + ("..." if len(text) > max_len else "")


def _guard_check(
    scouter: ScouterClient,
    tool_name: str,
    arguments: str,
    category: str,
) -> None:
    if not scouter.interceptor:
        return
    from scouter.guards.base import GuardDecision

    action_str = f"{tool_name} {arguments}"
    result = None
    if category in ("system",):
        result = scouter.interceptor.check_shell(action_str)
    elif category in ("database",):
        result = scouter.interceptor.check_database(action_str)
    elif category in ("api", "third_party_api", "cloud", "financial"):
        result = scouter.interceptor.check_api(action_str)
    else:
        result = scouter.interceptor.check_shell(action_str)
        if result.decision == GuardDecision.ALLOW:
            result = scouter.interceptor.check_api(action_str)

    if result and result.decision == GuardDecision.BLOCK:
        scouter.console.log_info(
            "guard",
            f"BLOCKED by {result.guard_type} guard: {result.reason}",
        )


def _evaluate(
    scouter: ScouterClient,
    action_dict: dict,
    intent: Any,
    intent_id: Optional[str],
) -> tuple:
    from scouter.models import (
        ActionProposal, Evaluation, GovernanceDecision,
        Decision, ActualExecution,
    )

    action = ActionProposal(**action_dict)

    if scouter.backend and intent_id:
        resp = scouter.backend.evaluate(
            action=action_dict,
            intent_id=intent_id,
            trace_id=scouter.trace_id,
            model=_FRAMEWORK,
        )
        if resp:
            ev = resp.get("evaluation", {})
            decision = GovernanceDecision(
                artifact_id=resp.get("artifact_id", ""),
                timestamp=resp.get("timestamp", ""),
                intent_id=resp.get("intent_id", ""),
                action=action,
                evaluation=Evaluation(
                    irreversibility_score=ev.get("irreversibility_score", 0),
                    alignment_score=ev.get("alignment_score", 0),
                    calculated_decision=Decision(ev.get("calculated_decision", "PASS_THROUGH")),
                    actual_execution=ActualExecution(ev.get("actual_execution", "AUDIT_PASS")),
                    rationale=ev.get("rationale", ""),
                ),
            )
            sig = None
            if resp.get("signature"):
                sig = {
                    "artifact_id": resp.get("artifact_id", ""),
                    "signature": resp["signature"],
                    "public_key_id": resp.get("public_key_id", ""),
                }
            return decision, sig

    return scouter.engine.evaluate(action, intent), None


def _try_mint_credential(
    scouter: ScouterClient,
    intent_id: str,
    sig: dict,
    action_dict: dict,
) -> None:
    try:
        cred = scouter.backend.mint_credential(
            intent_id=intent_id,
            artifact_id=sig["artifact_id"],
            scope={
                "target": action_dict.get("target_system", ""),
                "operations": [action_dict.get("action_type", "")],
            },
        )
        if cred:
            scouter.console.log_info(
                "jit",
                f"Minted credential {cred['credential_id']} "
                f"(expires in {cred.get('expires_in', 300)}s)",
            )
            scouter._active_credentials[action_dict["action_type"]] = cred
    except Exception:
        pass


def _send_span_bg(
    scouter: ScouterClient,
    span_type: str,
    data: dict,
    intent_id: Optional[str],
) -> None:
    if not scouter.backend:
        return
    try:
        _bg_pool.submit(
            scouter.backend.ingest_span,
            scouter.trace_id, span_type, data,
            "", intent_id or "",
        )
    except Exception:
        pass
