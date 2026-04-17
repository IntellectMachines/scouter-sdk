"""
Scouter CLI Console Logger.

Pretty-prints intercepted prompts, tool calls, governance decisions,
and behavioral observations to stdout with colour and structure.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from scouter.models import GovernanceDecision, Decision

# ANSI colour codes (gracefully degrade on non-TTY)
_COLORS_ENABLED = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_RESET = "\033[0m" if _COLORS_ENABLED else ""
_BOLD = "\033[1m" if _COLORS_ENABLED else ""
_DIM = "\033[2m" if _COLORS_ENABLED else ""
_CYAN = "\033[36m" if _COLORS_ENABLED else ""
_GREEN = "\033[32m" if _COLORS_ENABLED else ""
_YELLOW = "\033[33m" if _COLORS_ENABLED else ""
_RED = "\033[31m" if _COLORS_ENABLED else ""
_MAGENTA = "\033[35m" if _COLORS_ENABLED else ""
_BLUE = "\033[34m" if _COLORS_ENABLED else ""

_DECISION_COLORS = {
    Decision.PASS_THROUGH: _GREEN,
    Decision.FLAG: _YELLOW,
    Decision.PAUSE: _YELLOW,
    Decision.HARD_STOP: _RED,
    Decision.ESCALATE: _RED,
}

_DIVIDER = f"{_DIM}{'─' * 72}{_RESET}"


class ConsoleLogger:
    """Structured CLI output for Scouter audit events."""

    def __init__(self, verbose: bool = True) -> None:
        self.verbose = verbose

    # ── Public API ─────────────────────────────────────────────────────

    def log_request_intercepted(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Any]] = None,
    ) -> None:
        self._header("REQUEST INTERCEPTED")
        print(f"  {_CYAN}Model:{_RESET}  {model}")
        print(f"  {_CYAN}Messages:{_RESET}")
        for msg in messages:
            role = msg.get("role", "?")
            content = msg.get("content", "")
            color = _MAGENTA if role == "system" else _BLUE if role == "user" else _DIM
            label = role.upper().ljust(10)
            # Truncate long content for display
            display = self._truncate(str(content), 300)
            print(f"    {color}{label}{_RESET} {display}")
        if tools:
            names = []
            for t in tools:
                if isinstance(t, dict):
                    fn = t.get("function", {})
                    names.append(fn.get("name", "?"))
                else:
                    names.append(str(t))
            print(f"  {_CYAN}Tools:{_RESET}   {', '.join(names)}")
        print(_DIVIDER)

    def log_response_captured(
        self,
        model: str,
        finish_reason: Optional[str],
        content: Optional[str],
        tool_calls: Optional[List[Any]] = None,
    ) -> None:
        self._header("RESPONSE CAPTURED")
        print(f"  {_CYAN}Model:{_RESET}          {model}")
        print(f"  {_CYAN}Finish Reason:{_RESET}  {finish_reason or 'n/a'}")
        if content:
            print(f"  {_CYAN}Content:{_RESET}")
            print(f"    {self._truncate(content, 400)}")
        if tool_calls:
            print(f"  {_CYAN}Tool Calls:{_RESET}")
            for tc in tool_calls:
                name = getattr(tc, "function", None)
                if name:
                    fn_name = getattr(name, "name", str(name))
                    fn_args = getattr(name, "arguments", "")
                    print(f"    {_YELLOW}→ {fn_name}{_RESET}({self._truncate(str(fn_args), 120)})")
                else:
                    print(f"    {_YELLOW}→ {tc}{_RESET}")
        print(_DIVIDER)

    def log_governance_decision(self, decision: GovernanceDecision) -> None:
        ev = decision.evaluation
        color = _DECISION_COLORS.get(ev.calculated_decision, _DIM)
        self._header("GOVERNANCE DECISION (AUDIT)")
        print(f"  {_CYAN}Artifact ID:{_RESET}      {decision.artifact_id}")
        print(f"  {_CYAN}Timestamp:{_RESET}        {decision.timestamp}")
        print(f"  {_CYAN}Intent ID:{_RESET}        {decision.intent_id or '(none)'}")
        print(f"  {_CYAN}Action Type:{_RESET}      {decision.action.action_type}")
        print(f"  {_CYAN}Target System:{_RESET}    {decision.action.target_system}")
        print(f"  {_CYAN}Payload Summary:{_RESET}  {decision.action.payload_summary}")
        print(f"  {_CYAN}Irreversibility:{_RESET}  {ev.irreversibility_score}")
        print(f"  {_CYAN}Alignment Score:{_RESET}  {ev.alignment_score}")
        print(
            f"  {_CYAN}Calculated:{_RESET}      "
            f"{color}{_BOLD}{ev.calculated_decision.value}{_RESET}"
        )
        print(
            f"  {_CYAN}Actual Execution:{_RESET} "
            f"{_GREEN}{ev.actual_execution.value}{_RESET}"
        )
        print(f"  {_CYAN}Rationale:{_RESET}       {ev.rationale}")
        print(_DIVIDER)

    def log_behavioral_finding(
        self,
        failure_type: str,
        confidence: float,
        probable_cause: str,
    ) -> None:
        color = _RED if confidence > 0.7 else _YELLOW
        self._header("BEHAVIORAL FINDING (MODA)")
        print(f"  {_CYAN}Failure Type:{_RESET}   {color}{_BOLD}{failure_type}{_RESET}")
        print(f"  {_CYAN}Confidence:{_RESET}     {color}{confidence}{_RESET}")
        print(f"  {_CYAN}Probable Cause:{_RESET} {probable_cause}")
        print(_DIVIDER)

    def log_signature(self, artifact_id: str, signature: str, key_id: str) -> None:
        self._header("CRYPTOGRAPHIC SIGNATURE (Ed25519)")
        print(f"  {_CYAN}Artifact ID:{_RESET}  {artifact_id}")
        print(f"  {_CYAN}Key ID:{_RESET}       {key_id}")
        print(f"  {_CYAN}Signature:{_RESET}    {_DIM}{signature[:64]}...{_RESET}")
        print(_DIVIDER)

    def log_tool_executed(
        self,
        tool_name: str,
        arguments: str,
        result: str,
    ) -> None:
        self._header("TOOL EXECUTED")
        print(f"  {_CYAN}Tool:{_RESET}       {_YELLOW}{tool_name}{_RESET}")
        print(f"  {_CYAN}Arguments:{_RESET}  {self._truncate(arguments, 300)}")
        is_error = result.startswith("ERROR")
        result_color = _RED if is_error else _GREEN
        print(f"  {_CYAN}Result:{_RESET}     {result_color}{self._truncate(result, 300)}{_RESET}")
        print(_DIVIDER)

    def log_agent_loop(self, iteration: int, status: str) -> None:
        print()
        print(f"  {_BOLD}{_MAGENTA}── Agent Loop #{iteration} │ {status} ──{_RESET}")

    def log_info(self, tag: str, message: str) -> None:
        print(f"  {_DIM}[scouter:{tag}]{_RESET} {message}")

    def log_prompt_analysis(self, analysis: dict) -> None:
        """Pretty-print a prompt analysis result from the Scouter engine."""
        decision = analysis.get("decision", "UNKNOWN")
        alert = analysis.get("alert_level", "UNKNOWN")
        risk_score = analysis.get("risk_score", 0)
        intent_info = analysis.get("intent", {})
        risk_info = analysis.get("risk", {})
        severity_info = analysis.get("severity", {})
        consequence = analysis.get("consequence", {})

        # Pick color based on alert level
        if alert == "CRITICAL":
            alert_color = _RED
            icon = "🚨"
        elif alert == "WARNING":
            alert_color = _YELLOW
            icon = "⚠️"
        elif alert == "CAUTION":
            alert_color = _YELLOW
            icon = "⚡"
        else:
            alert_color = _GREEN
            icon = "✅"

        # Decision color
        if decision in ("REJECTED",):
            dec_color = _RED
        elif decision in ("REQUIRES_REVIEW",):
            dec_color = _YELLOW
        elif decision in ("ALLOWED_WITH_CAUTION",):
            dec_color = _YELLOW
        else:
            dec_color = _GREEN

        self._header(f"PROMPT ANALYSIS {icon}")
        print(f"  {_CYAN}Analysis ID:{_RESET}    {analysis.get('analysis_id', 'N/A')}")
        print(f"  {_CYAN}Intent:{_RESET}         {intent_info.get('label', '?')} ({intent_info.get('confidence', 0)*100:.1f}%)")
        print(f"  {_CYAN}Risk Category:{_RESET}  {risk_info.get('category', '?')} ({risk_info.get('confidence', 0)*100:.1f}%)")
        print(f"  {_CYAN}Severity:{_RESET}       {severity_info.get('level', '?')} ({severity_info.get('confidence', 0)*100:.1f}%)")
        print(f"  {_CYAN}Risk Score:{_RESET}     {alert_color}{_BOLD}{risk_score}/100{_RESET}")
        print(f"  {_CYAN}Decision:{_RESET}       {dec_color}{_BOLD}{decision}{_RESET}")
        print(f"  {_CYAN}Alert Level:{_RESET}    {alert_color}{_BOLD}[{alert}]{_RESET}")
        if consequence.get("description"):
            print(f"  {_CYAN}Consequence:{_RESET}   {consequence['description']}")
        if consequence.get("real_world_impact"):
            print(f"  {_CYAN}Real-World:{_RESET}    {consequence['real_world_impact']}")
        if consequence.get("mitigation"):
            print(f"  {_CYAN}Mitigation:{_RESET}    {consequence['mitigation']}")
        print(f"  {_CYAN}Latency:{_RESET}        {analysis.get('latency_ms', 0):.0f}ms")
        print(_DIVIDER)

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _header(title: str) -> None:
        print()
        print(f"  {_BOLD}{_CYAN}◆ SCOUTER │ {title}{_RESET}")
        print(_DIVIDER)

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len] + f" {_DIM}…(truncated){_RESET}"
