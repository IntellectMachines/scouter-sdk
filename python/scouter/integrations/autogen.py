"""
Scouter <> AutoGen Integration.

Two complementary hooks:

1. **Message interceptor** -- ``wrap_autogen_agent`` registers a
   ``reply_func`` on an ``AssistantAgent`` that inspects every outbound
   message for ``tool_calls`` and runs them through the Scouter pipeline
   (triage -> guards -> consequence engine) *before* execution.

2. **Function-map wrapper** -- ``wrap_autogen_functions`` patches the
   ``function_map`` dict on a ``UserProxyAgent`` so that each registered
   function is individually governed by Scouter.

Usage::

    from autogen import AssistantAgent, UserProxyAgent
    from scouter.client import ScouterClient
    from scouter.integrations.autogen import (
        wrap_autogen_agent,
        wrap_autogen_functions,
    )

    scouter = ScouterClient(backend_url="http://localhost:8000")

    assistant  = AssistantAgent("assistant", llm_config=llm_config)
    user_proxy = UserProxyAgent("user", function_map={...})

    # Option A -- intercept assistant messages containing tool_calls
    wrap_autogen_agent(assistant, scouter, intent_id="...")

    # Option B -- wrap individual functions on the proxy
    wrap_autogen_functions(user_proxy, scouter, intent_id="...")
"""

from __future__ import annotations

import functools
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional

from scouter.client import ScouterClient
from scouter.classifier.action_triage import TriageVerdict

_bg_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scouter-ag")

_FRAMEWORK = "autogen"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def wrap_autogen_agent(
    agent: Any,
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> Any:
    """
    Register a ``reply_func`` on an AutoGen agent that intercepts outbound
    messages containing ``tool_calls``.

    This uses AutoGen's ``register_reply()`` mechanism so it works with
    ``AssistantAgent``, ``ConversableAgent``, and any subclass.

    Args:
        agent:      An AutoGen agent instance.
        scouter:    A configured ``ScouterClient``.
        intent_id:  The Intent ID to evaluate actions against.

    Returns:
        The same agent with the reply hook registered.
    """
    intent = scouter.registry.get(intent_id) if intent_id else None

    def _scouter_reply_hook(
        recipient: Any,
        messages: Optional[List[dict]] = None,
        sender: Any = None,
        config: Any = None,
    ) -> tuple:
        """
        AutoGen reply hook.  Returns ``(False, None)`` to let the normal
        reply pipeline continue.  If a HARD_STOP is detected in enforce
        mode, returns ``(True, <blocked message>)`` to short-circuit.
        """
        if not messages:
            return False, None

        last = messages[-1] if messages else {}

        # Check for tool_calls in the message
        tool_calls = last.get("tool_calls") or []
        if not tool_calls and isinstance(last.get("content"), str):
            # Some AutoGen versions embed function_call in content
            return False, None

        for tc in tool_calls:
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            fn_name = fn.get("name", "unknown")
            fn_args = fn.get("arguments", "")

            triage = scouter.classifier.classify_tool_call(fn_name, fn_args)

            if triage.verdict == TriageVerdict.SKIP:
                scouter.console.log_info(
                    "triage",
                    f"SKIP  {fn_name}  ({triage.reason}) [{triage.elapsed_us:.1f}\u00b5s]",
                )
                _send_span_bg(scouter, "tool_call", {
                    "tool_name": fn_name, "arguments": fn_args,
                    "triage": "SKIP", "framework": _FRAMEWORK,
                }, intent_id)
                continue

            scouter.console.log_info(
                "triage",
                f"SCAN  {fn_name}  [{triage.category}] {triage.reason} [{triage.elapsed_us:.1f}\u00b5s]",
            )

            action_dict = {
                "action_type": fn_name,
                "target_system": triage.category,
                "payload_summary": _truncate(fn_args, 200),
                "delegation_depth": 0,
            }

            _send_span_bg(scouter, "tool_call", {
                "tool_name": fn_name, "arguments": fn_args,
                "triage": "SCAN", "triage_category": triage.category,
                "framework": _FRAMEWORK,
            }, intent_id)

            _guard_check(scouter, fn_name, fn_args, triage.category)

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
                return True, {
                    "content": (
                        f"[Scouter] HARD_STOP: {fn_name} blocked -- "
                        f"{decision.evaluation.rationale}"
                    ),
                    "role": "assistant",
                }

        # Let the normal reply pipeline continue
        return False, None

    # AutoGen's register_reply inserts at highest priority by default
    if hasattr(agent, "register_reply"):
        agent.register_reply(
            trigger=lambda *_a, **_kw: True,  # fire on every message
            reply_func=_scouter_reply_hook,
            position=0,  # run before all other reply functions
        )

    scouter.console.log_info(
        _FRAMEWORK,
        f"Registered Scouter reply hook on AutoGen agent "
        f"'{getattr(agent, 'name', '?')}' -- messages are now audited.",
    )
    return agent


def wrap_autogen_functions(
    agent: Any,
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> Any:
    """
    Wrap every function in an AutoGen agent's ``function_map`` with
    Scouter governance.

    Args:
        agent:      An AutoGen ``UserProxyAgent`` (or any agent with a
                    ``function_map`` dict).
        scouter:    A configured ``ScouterClient``.
        intent_id:  The Intent ID to evaluate actions against.

    Returns:
        The same agent with function_map entries patched.
    """
    fn_map: Optional[dict] = getattr(agent, "function_map", None)
    if not fn_map:
        scouter.console.log_info(
            _FRAMEWORK,
            f"Agent '{getattr(agent, 'name', '?')}' has no function_map -- nothing to wrap.",
        )
        return agent

    intent = scouter.registry.get(intent_id) if intent_id else None

    for fn_name, fn_callable in list(fn_map.items()):
        fn_map[fn_name] = _make_wrapped_function(
            fn_name, fn_callable, scouter, intent, intent_id,
        )

    scouter.console.log_info(
        _FRAMEWORK,
        f"Wrapped {len(fn_map)} function(s) on AutoGen agent "
        f"'{getattr(agent, 'name', '?')}' -- all executions are now audited.",
    )
    return agent


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_wrapped_function(
    fn_name: str,
    fn_callable: Callable,
    scouter: ScouterClient,
    intent: Any,
    intent_id: Optional[str],
) -> Callable:
    """Return a wrapped version of *fn_callable* with Scouter governance."""

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
