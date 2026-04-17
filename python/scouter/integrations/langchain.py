"""
Scouter <> LangChain Integration.

Wraps LangChain ``BaseTool`` instances so that every ``_run`` /
``_arun`` call is transparently intercepted by Scouter:

1. Tool name + args classified by the **Action Triage Classifier**.
2. SKIP actions pass through instantly (the 85-95 % fast path).
3. SCAN actions checked by **Execution Guards** + **Consequence Engine**.
4. Trace spans sent to the backend for behavioural analysis.
5. JIT credentials auto-minted on PASS_THROUGH decisions.

Usage::

    from langchain.tools import BaseTool
    from scouter.client import ScouterClient
    from scouter.integrations.langchain import wrap_langchain_tools

    scouter = ScouterClient(backend_url="http://localhost:8000")
    intent  = scouter.registry.register(
        agent_id="finance-agent-v1",
        intent="Read DB and generate internal financial reports.",
        permitted_domains=["internal-db", "reporting"],
    )
    safe_tools = wrap_langchain_tools(my_tools, scouter, intent_id=intent.id)
"""

from __future__ import annotations

import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any, List, Optional

from scouter.client import ScouterClient
from scouter.classifier.action_triage import TriageVerdict

_bg_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scouter-lc")

_FRAMEWORK = "langchain"


# ---------------------------------------------------------------------------
# Public helpers (legacy alias used in STD examples)
# ---------------------------------------------------------------------------

class ScouterToolWrapper:
    """Convenience class matching the STD section 4.1 example API."""

    @staticmethod
    def wrap_all(
        tools: List[Any],
        client: ScouterClient,
        *,
        intent_id: Optional[str] = None,
    ) -> List[Any]:
        """Wrap every tool in *tools* with Scouter governance."""
        return wrap_langchain_tools(tools, client, intent_id=intent_id)

    @staticmethod
    def wrap(
        tool: Any,
        client: ScouterClient,
        *,
        intent_id: Optional[str] = None,
    ) -> Any:
        """Wrap a single tool."""
        return wrap_langchain_tool(tool, client, intent_id=intent_id)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def wrap_langchain_tools(
    tools: List[Any],
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> List[Any]:
    """
    Wrap a list of LangChain ``BaseTool`` instances with Scouter governance.

    Args:
        tools:      List of LangChain tools (``BaseTool`` subclasses).
        scouter:    A configured ``ScouterClient``.
        intent_id:  The Intent ID to evaluate actions against.

    Returns:
        The same list with ``_run`` / ``_arun`` patched in-place.
    """
    intent = scouter.registry.get(intent_id) if intent_id else None

    for tool in tools:
        _patch_tool(tool, scouter, intent, intent_id)

    scouter.console.log_info(
        _FRAMEWORK,
        f"Wrapped {len(tools)} LangChain tool(s) -- all executions are now audited.",
    )
    return tools


def wrap_langchain_tool(
    tool: Any,
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> Any:
    """Wrap a single LangChain ``BaseTool`` with Scouter governance."""
    intent = scouter.registry.get(intent_id) if intent_id else None
    _patch_tool(tool, scouter, intent, intent_id)
    scouter.console.log_info(
        _FRAMEWORK,
        f"Wrapped tool '{getattr(tool, 'name', '?')}' -- executions are now audited.",
    )
    return tool


# ---------------------------------------------------------------------------
# Internal patching
# ---------------------------------------------------------------------------

def _patch_tool(
    tool: Any,
    scouter: ScouterClient,
    intent: Any,
    intent_id: Optional[str],
) -> None:
    """Monkey-patch ``_run`` and ``_arun`` on a LangChain ``BaseTool``."""
    tool_name = getattr(tool, "name", None) or type(tool).__name__
    original_run = tool._run

    @functools.wraps(original_run)
    def _wrapped_run(*args: Any, **kwargs: Any) -> Any:
        return _intercept(
            original_run, args, kwargs,
            tool_name=tool_name,
            scouter=scouter,
            intent=intent,
            intent_id=intent_id,
        )

    tool._run = _wrapped_run

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

    # SCAN path
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
# Shared helpers (same patterns as openai.py)
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
