"""
Scouter <> CrewAI Integration.

Wraps CrewAI ``Tool`` instances so that every invocation is
transparently intercepted by Scouter.  Also provides a helper to
wrap an entire ``Agent`` (all its tools at once).

CrewAI tools extend LangChain's ``BaseTool`` so the patching strategy
is identical: override ``_run`` / ``_arun``.

Usage::

    from crewai import Agent, Task, Crew
    from crewai_tools import SomeTool
    from scouter.client import ScouterClient
    from scouter.integrations.crewai import wrap_crewai_tools, wrap_crewai_agent

    scouter = ScouterClient(backend_url="http://localhost:8000")

    # Option A -- wrap individual tools
    safe_tools = wrap_crewai_tools([SomeTool()], scouter, intent_id="...")

    # Option B -- wrap the agent (patches all tools it carries)
    agent = Agent(role="analyst", tools=[SomeTool()], ...)
    wrap_crewai_agent(agent, scouter, intent_id="...")
"""

from __future__ import annotations

import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any, List, Optional

from scouter.client import ScouterClient
from scouter.classifier.action_triage import TriageVerdict

_bg_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scouter-crew")

_FRAMEWORK = "crewai"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def wrap_crewai_tools(
    tools: List[Any],
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> List[Any]:
    """
    Wrap a list of CrewAI tools with Scouter governance.

    Args:
        tools:      List of CrewAI ``Tool`` instances.
        scouter:    A configured ``ScouterClient``.
        intent_id:  The Intent ID to evaluate actions against.

    Returns:
        The same list with execution methods patched in-place.
    """
    intent = scouter.registry.get(intent_id) if intent_id else None

    for tool in tools:
        _patch_tool(tool, scouter, intent, intent_id)

    scouter.console.log_info(
        _FRAMEWORK,
        f"Wrapped {len(tools)} CrewAI tool(s) -- all executions are now audited.",
    )
    return tools


def wrap_crewai_agent(
    agent: Any,
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> Any:
    """
    Wrap a CrewAI ``Agent`` so all its tools are governed by Scouter.

    Args:
        agent:      A CrewAI ``Agent`` instance.
        scouter:    A configured ``ScouterClient``.
        intent_id:  The Intent ID to evaluate actions against.

    Returns:
        The same agent with tools patched.
    """
    if hasattr(agent, "tools") and agent.tools:
        wrap_crewai_tools(agent.tools, scouter, intent_id=intent_id)

    scouter.console.log_info(
        _FRAMEWORK,
        f"Wrapped CrewAI agent '{getattr(agent, 'role', 'unknown')}' "
        f"-- all tool executions are now audited.",
    )
    return agent


# ---------------------------------------------------------------------------
# Internal patching
# ---------------------------------------------------------------------------

def _patch_tool(
    tool: Any,
    scouter: ScouterClient,
    intent: Any,
    intent_id: Optional[str],
) -> None:
    """Monkey-patch ``_run`` on a CrewAI Tool instance."""
    # CrewAI tools usually expose ``_run``; some older versions use ``func``
    if hasattr(tool, "_run"):
        attr_name = "_run"
    elif hasattr(tool, "func") and callable(getattr(tool, "func", None)):
        attr_name = "func"
    else:
        return

    original_fn = getattr(tool, attr_name)
    tool_name = getattr(tool, "name", None) or type(tool).__name__

    @functools.wraps(original_fn)
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        return _intercept(
            original_fn, args, kwargs,
            tool_name=tool_name,
            scouter=scouter,
            intent=intent,
            intent_id=intent_id,
        )

    setattr(tool, attr_name, _wrapped)

    # Patch async variant if present
    if hasattr(tool, "_arun"):
        original_arun = tool._arun

        @functools.wraps(original_arun)
        async def _wrapped_arun(*args: Any, **kwargs: Any) -> Any:
            return await _intercept_async(
                original_arun, args, kwargs,
                tool_name=tool_name,
                scouter=scouter,
                intent=intent,
                intent_id=intent_id,
            )

        tool._arun = _wrapped_arun


# ---------------------------------------------------------------------------
# Intercept logic (sync + async)
# ---------------------------------------------------------------------------

def _intercept(
    original_fn: Any,
    args: tuple,
    kwargs: dict,
    *,
    tool_name: str,
    scouter: ScouterClient,
    intent: Any,
    intent_id: Optional[str],
) -> Any:
    tool_input = _build_input_str(args, kwargs)
    triage = scouter.classifier.classify_tool_call(tool_name, tool_input)

    if triage.verdict == TriageVerdict.SKIP:
        scouter.console.log_info(
            "triage",
            f"SKIP  {tool_name}  ({triage.reason}) [{triage.elapsed_us:.1f}\u00b5s]",
        )
        _send_span_bg(scouter, "tool_call", {
            "tool_name": tool_name, "arguments": tool_input,
            "triage": "SKIP", "framework": _FRAMEWORK,
        }, intent_id)
        return original_fn(*args, **kwargs)

    scouter.console.log_info(
        "triage",
        f"SCAN  {tool_name}  [{triage.category}] {triage.reason} [{triage.elapsed_us:.1f}\u00b5s]",
    )

    action_dict = {
        "action_type": tool_name,
        "target_system": triage.category,
        "payload_summary": _truncate(tool_input, 200),
        "delegation_depth": 0,
    }

    _send_span_bg(scouter, "tool_call", {
        "tool_name": tool_name, "arguments": tool_input,
        "triage": "SCAN", "triage_category": triage.category,
        "framework": _FRAMEWORK,
    }, intent_id)

    _guard_check(scouter, tool_name, tool_input, triage.category)

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
            f"Scouter HARD_STOP: {tool_name} blocked -- "
            f"{decision.evaluation.rationale}"
        )

    return original_fn(*args, **kwargs)


async def _intercept_async(
    original_fn: Any,
    args: tuple,
    kwargs: dict,
    *,
    tool_name: str,
    scouter: ScouterClient,
    intent: Any,
    intent_id: Optional[str],
) -> Any:
    tool_input = _build_input_str(args, kwargs)
    triage = scouter.classifier.classify_tool_call(tool_name, tool_input)

    if triage.verdict == TriageVerdict.SKIP:
        scouter.console.log_info(
            "triage",
            f"SKIP  {tool_name}  ({triage.reason}) [{triage.elapsed_us:.1f}\u00b5s]",
        )
        return await original_fn(*args, **kwargs)

    scouter.console.log_info(
        "triage",
        f"SCAN  {tool_name}  [{triage.category}] {triage.reason} [{triage.elapsed_us:.1f}\u00b5s]",
    )

    action_dict = {
        "action_type": tool_name,
        "target_system": triage.category,
        "payload_summary": _truncate(tool_input, 200),
        "delegation_depth": 0,
    }

    _guard_check(scouter, tool_name, tool_input, triage.category)
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
            f"Scouter HARD_STOP: {tool_name} blocked -- "
            f"{decision.evaluation.rationale}"
        )

    return await original_fn(*args, **kwargs)


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
