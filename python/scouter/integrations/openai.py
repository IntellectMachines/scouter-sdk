"""
Scouter <> OpenAI Integration.

Wraps an ``openai.OpenAI`` client so that every call to
``chat.completions.create`` is transparently intercepted:

1. **Before** the request  -> captures prompt / messages / tools.
2. The request executes normally against the OpenAI API.
3. **After** the response  -> captures completions, tool_calls.
4. Each tool_call is classified by the **Action Triage Classifier**:
   - SKIP  -> benign action, no backend call (the 85-95% fast path)
   - SCAN  -> actionable content, evaluated by backend + guards
5. SCAN actions are checked by the **Execution Interceptor** (guards)
   and evaluated by the Consequence Engine.  BLOCK = action rejected.
6. Trace spans are sent to the backend for behavioural analysis.
7. Returns the original response object untouched.

The wrapper returns the original response object untouched so downstream
code is completely unaffected (in audit mode).
"""

from __future__ import annotations

import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from scouter.client import ScouterClient
from scouter.models import ActionProposal
from scouter.classifier.action_triage import TriageVerdict

# Shared pool for background tasks (spans, analysis)
_bg_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scouter-bg")


def wrap_openai(
    openai_client: Any,
    scouter: ScouterClient,
    *,
    intent_id: Optional[str] = None,
) -> Any:
    """
    Wrap an ``openai.OpenAI()`` instance with Scouter instrumentation.

    Args:
        openai_client: An instantiated ``openai.OpenAI`` client.
        scouter:       A configured ``ScouterClient``.
        intent_id:     The Intent ID to evaluate actions against.

    Returns:
        The same client object, with ``chat.completions.create`` patched.
    """
    intent = scouter.registry.get(intent_id) if intent_id else None

    original_create = openai_client.chat.completions.create

    @functools.wraps(original_create)
    def _wrapped_create(*args: Any, **kwargs: Any) -> Any:
        model = kwargs.get("model", args[0] if args else "unknown")
        messages = kwargs.get("messages", args[1] if len(args) > 1 else [])
        tools = kwargs.get("tools", None)
        msg_dicts = [_msg_to_dict(m) for m in messages]

        # ---- 1. Log the outbound request ----
        scouter.console.log_request_intercepted(
            model=str(model),
            messages=msg_dicts,
            tools=tools,
        )

        # ---- 1b. Triage the latest user prompt ----
        # Only send actionable prompts to backend for ML analysis.
        # Conversational prompts ("What's your return policy?") are skipped.
        last_user_msg = _get_last_user_message(msg_dicts)
        if last_user_msg and scouter.backend:
            prompt_triage = scouter.classifier.classify_prompt(last_user_msg)
            if prompt_triage.verdict == TriageVerdict.SCAN:
                scouter.console.log_info(
                    "triage",
                    f"SCAN prompt  [{prompt_triage.category}] "
                    f"{prompt_triage.reason} [{prompt_triage.elapsed_us:.1f}us]",
                )
                _bg_pool.submit(
                    _analyze_prompt_bg, scouter, last_user_msg, intent_id,
                )
            else:
                scouter.console.log_info(
                    "triage",
                    f"SKIP prompt  ({prompt_triage.reason}) [{prompt_triage.elapsed_us:.1f}us]",
                )

        # Send request span to backend (background)
        _send_span_bg(scouter, "request", {
            "model": str(model),
            "messages": msg_dicts,
            "tools": _tool_names(tools),
        }, intent_id)

        # ---- 2. Execute the real OpenAI call ----
        response = original_create(*args, **kwargs)

        # ---- 3. Capture the response ----
        choice = response.choices[0] if response.choices else None
        finish_reason = getattr(choice, "finish_reason", None) if choice else None
        message = getattr(choice, "message", None) if choice else None
        content = getattr(message, "content", None) if message else None
        tool_calls = getattr(message, "tool_calls", None) if message else None

        scouter.console.log_response_captured(
            model=response.model or str(model),
            finish_reason=finish_reason,
            content=content,
            tool_calls=tool_calls,
        )

        # Send response span to backend (background)
        tc_data = []
        if tool_calls:
            for tc in tool_calls:
                fn = getattr(tc, "function", None)
                tc_data.append({
                    "name": getattr(fn, "name", "?") if fn else "?",
                    "arguments": getattr(fn, "arguments", "") if fn else "",
                })
        _send_span_bg(scouter, "response", {
            "content": content,
            "tool_calls": tc_data,
            "tools_available": bool(tools),
            "finish_reason": finish_reason,
        }, intent_id)

        actual_model = response.model or str(model)

        # ---- 4. Triage + Evaluate each tool call ----
        if tool_calls:
            for tc in tool_calls:
                fn = getattr(tc, "function", None)
                fn_name = getattr(fn, "name", "unknown") if fn else "unknown"
                fn_args = getattr(fn, "arguments", "") if fn else ""

                # ACTION TRIAGE: classify this tool call
                triage = scouter.classifier.classify_tool_call(fn_name, fn_args)

                if triage.verdict == TriageVerdict.SKIP:
                    # Fast path: benign action, no backend evaluation
                    scouter.console.log_info(
                        "triage",
                        f"SKIP  {fn_name}  ({triage.reason}) [{triage.elapsed_us:.1f}us]",
                    )
                    # Send tool_call span for observability (background)
                    _send_span_bg(scouter, "tool_call", {
                        "tool_name": fn_name,
                        "arguments": fn_args,
                        "triage": "SKIP",
                    }, intent_id)
                    continue

                # SCAN path: actionable content -- full evaluation
                scouter.console.log_info(
                    "triage",
                    f"SCAN  {fn_name}  [{triage.category}] {triage.reason} [{triage.elapsed_us:.1f}us]",
                )

                action_dict = {
                    "action_type": fn_name,
                    "target_system": triage.category,
                    "payload_summary": _truncate(str(fn_args), 200),
                    "delegation_depth": 0,
                }

                # Send tool_call span
                _send_span_bg(scouter, "tool_call", {
                    "tool_name": fn_name,
                    "arguments": fn_args,
                    "triage": "SCAN",
                    "triage_category": triage.category,
                }, intent_id)

                # Run through execution guards (shell/DB/API)
                _guard_check(scouter, fn_name, fn_args, triage.category)

                # Evaluate via backend Consequence Engine
                decision, sig = _evaluate(scouter, action_dict, intent, intent_id, model=actual_model)
                scouter.console.log_governance_decision(decision)
                if sig:
                    scouter.console.log_signature(
                        sig["artifact_id"], sig["signature"], sig["public_key_id"],
                    )

                # Auto-mint JIT credential on PASS_THROUGH
                if sig and scouter.backend and intent_id:
                    _try_mint_credential(scouter, intent_id, sig, action_dict)
        else:
            # Text completion -- triage the content
            triage = scouter.classifier.classify_completion(content or "")

            if triage.verdict == TriageVerdict.SKIP:
                scouter.console.log_info(
                    "triage",
                    f"SKIP  llm:completion  ({triage.reason}) [{triage.elapsed_us:.1f}us]",
                )
            else:
                scouter.console.log_info(
                    "triage",
                    f"SCAN  llm:completion  [{triage.category}] {triage.reason}",
                )
                action_dict = {
                    "action_type": "llm:completion",
                    "target_system": triage.category,
                    "payload_summary": _truncate(content or "(empty)", 200),
                    "delegation_depth": 0,
                }
                decision, sig = _evaluate(scouter, action_dict, intent, intent_id, model=actual_model)
                scouter.console.log_governance_decision(decision)
                if sig:
                    scouter.console.log_signature(
                        sig["artifact_id"], sig["signature"], sig["public_key_id"],
                    )

        # ---- 5. Trigger behavioral analysis (background) ----
        if scouter.backend:
            _bg_pool.submit(_analyze_bg, scouter)

        # ---- 6. Return original response untouched ----
        return response

    openai_client.chat.completions.create = _wrapped_create

    scouter.console.log_info(
        "openai",
        "OpenAI client wrapped -- all chat.completions.create calls are now audited.",
    )
    scouter.console.log_info(
        "triage",
        f"Action Triage Classifier active -- safe tools fast-pass, actionable content scanned.",
    )
    return openai_client


# ---- Guard Check ----

def _guard_check(
    scouter: ScouterClient,
    tool_name: str,
    arguments: str,
    category: str,
) -> None:
    """
    Run the tool call through execution guards based on its triage category.
    In audit mode, BLOCK decisions are logged but not enforced.
    In enforce/hybrid mode, BLOCK raises PermissionError.
    """
    if not scouter.interceptor:
        return

    from scouter.guards.base import GuardDecision

    # Build the action string for guard analysis
    action_str = f"{tool_name} {arguments}"

    result = None
    if category in ("system",):
        result = scouter.interceptor.check_shell(action_str)
    elif category in ("database",):
        result = scouter.interceptor.check_database(action_str)
    elif category in ("api", "third_party_api", "cloud", "financial"):
        result = scouter.interceptor.check_api(action_str)
    else:
        # Auto-detect for unknown categories
        result = scouter.interceptor.check_shell(action_str)
        if result.decision == GuardDecision.ALLOW:
            result = scouter.interceptor.check_api(action_str)

    if result and result.decision == GuardDecision.BLOCK:
        scouter.console.log_info(
            "guard",
            f"BLOCKED by {result.guard_type} guard: {result.reason}",
        )
        if scouter.mode == "enforce":
            raise PermissionError(
                f"Scouter guard BLOCKED: {result.reason}"
            )


# ---- JIT Credential Minting ----

def _try_mint_credential(
    scouter: ScouterClient,
    intent_id: str,
    sig: dict,
    action_dict: dict,
) -> None:
    """Attempt to mint a JIT credential after a PASS_THROUGH decision."""
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
                f"Minted credential {cred['credential_id']} (expires in {cred.get('expires_in', 300)}s)",
            )
            scouter._active_credentials[action_dict["action_type"]] = cred
    except Exception:
        pass  # Non-critical


# ---- Helpers ----


def _evaluate(
    scouter: ScouterClient,
    action_dict: dict,
    intent: Any,
    intent_id: Optional[str],
    model: Optional[str] = None,
) -> tuple[Any, Optional[dict]]:
    """Evaluate via backend if available, else local engine.
    Returns (GovernanceDecision, optional_signature_info)."""
    from scouter.models import (
        ActionProposal, Evaluation, GovernanceDecision,
        Decision, ActualExecution,
    )

    if scouter.backend and intent_id:
        result = scouter.backend.evaluate(
            action_dict,
            intent_id,
            trace_id=scouter.trace_id,
            model=model,
        )
        if result:
            ev = result.get("evaluation", {})
            decision = GovernanceDecision(
                artifact_id=result.get("artifact_id", ""),
                timestamp=result.get("timestamp", ""),
                intent_id=result.get("intent_id", ""),
                action=ActionProposal(
                    action_type=action_dict.get("action_type", ""),
                    target_system=action_dict.get("target_system", ""),
                    payload_summary=action_dict.get("payload_summary", ""),
                    delegation_depth=action_dict.get("delegation_depth", 0),
                ),
                evaluation=Evaluation(
                    irreversibility_score=ev.get("irreversibility_score", 0),
                    alignment_score=ev.get("alignment_score", 0),
                    calculated_decision=Decision(ev.get("calculated_decision", "PASS_THROUGH")),
                    actual_execution=ActualExecution(ev.get("actual_execution", "AUDIT_PASS")),
                    rationale=ev.get("rationale", ""),
                ),
            )
            sig_info = None
            if result.get("signature"):
                sig_info = {
                    "artifact_id": result.get("artifact_id", ""),
                    "signature": result["signature"],
                    "public_key_id": result.get("public_key_id", ""),
                }

            # Enforcement: block execution when backend returns BLOCKED/ESCALATE
            if ev.get("actual_execution") == "BLOCKED":
                scouter.console.log_info(
                    "enforce",
                    f"ACTION BLOCKED: {action_dict.get('action_type')} -> {ev.get('rationale', '')}",
                )
                if scouter.mode == "enforce":
                    raise PermissionError(
                        f"Scouter BLOCKED action '{action_dict.get('action_type')}': "
                        f"{ev.get('rationale', 'High-risk action denied by governance policy')}"
                    )
            elif ev.get("actual_execution") == "ESCALATE":
                scouter.console.log_info(
                    "enforce",
                    f"ACTION ESCALATED: {action_dict.get('action_type')} requires human approval",
                )
                if scouter.mode == "enforce":
                    raise PermissionError(
                        f"Scouter ESCALATED action '{action_dict.get('action_type')}': "
                        f"Requires human approval before execution"
                    )

            return decision, sig_info

    # Fallback to local
    action = ActionProposal(
        action_type=action_dict["action_type"],
        target_system=action_dict.get("target_system", ""),
        payload_summary=action_dict.get("payload_summary", ""),
        delegation_depth=action_dict.get("delegation_depth", 0),
    )
    return scouter.engine.evaluate(action, intent), None


def _send_span_bg(
    scouter: ScouterClient,
    span_type: str,
    data: dict,
    intent_id: Optional[str],
) -> None:
    """Send a trace span to the backend via the shared thread pool."""
    if not scouter.backend:
        return
    _bg_pool.submit(
        scouter.backend.ingest_span,
        scouter.trace_id, span_type, data,
        agent_id="", intent_id=intent_id or "",
    )


def _analyze_bg(scouter: ScouterClient) -> None:
    """Run behavioral analysis on the current trace."""
    if not scouter.backend:
        return
    import time
    time.sleep(0.3)  # let spans land first
    result = scouter.backend.analyze_trace(scouter.trace_id)
    if result and result.get("findings"):
        for f in result["findings"]:
            scouter.console.log_behavioral_finding(
                failure_type=f["failure_type"],
                confidence=f["confidence"],
                probable_cause=f.get("probable_cause", ""),
            )


def _msg_to_dict(msg: Any) -> dict:
    if isinstance(msg, dict):
        return msg
    return {
        "role": getattr(msg, "role", "?"),
        "content": getattr(msg, "content", ""),
    }


def _tool_names(tools: Any) -> list[str]:
    if not tools:
        return []
    names = []
    for t in tools:
        if isinstance(t, dict):
            names.append(t.get("function", {}).get("name", "?"))
        else:
            names.append(str(t))
    return names


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def _get_last_user_message(msg_dicts: list[dict]) -> Optional[str]:
    """Extract the content of the most recent user message."""
    for msg in reversed(msg_dicts):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str) and content.strip():
                return content.strip()
    return None


def _analyze_prompt_bg(
    scouter: ScouterClient,
    prompt: str,
    intent_id: Optional[str],
) -> None:
    """Send an actionable prompt to the backend for ML-based analysis (background)."""
    if not scouter.backend:
        return
    try:
        analysis = scouter.backend.analyze_prompt(
            prompt=prompt,
            intent_id=intent_id,
            agent_id="",
        )
        if analysis:
            scouter.console.log_prompt_analysis(analysis)
    except Exception:
        pass  # Non-critical
