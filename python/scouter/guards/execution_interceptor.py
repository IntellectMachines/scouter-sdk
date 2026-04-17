"""
ExecutionInterceptor — Central orchestrator for all execution guards.

Supports THREE modes:
  enforce  — Full local guards (all 60+ regex rules on client)
  audit    — Like enforce but BLOCK → WARN (logging only)
  hybrid   — LightGuard locally (sub-μs), suspicious actions → server

The hybrid mode is recommended for production:
  - 99% of benign actions pass instantly on the client (no network)
  - ~1% suspicious actions get full server-side validation (60+ rules)
  - Falls back to full local guards if server is unreachable
"""

from __future__ import annotations

import functools
import sys
from typing import Any, Callable, Dict, List, Optional

from scouter.guards.base import GuardDecision, GuardResult
from scouter.guards.shell_guard import ShellGuard
from scouter.guards.database_guard import DatabaseGuard
from scouter.guards.api_guard import APIGuard
from scouter.guards.light_guard import LightGuard
from scouter.guards.server_guard import ServerGuard

# ── ANSI colours ──────────────────────────────────────────────────────────
_TTY = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
_R   = "\033[91m" if _TTY else ""
_Y   = "\033[93m" if _TTY else ""
_G   = "\033[92m" if _TTY else ""
_C   = "\033[96m" if _TTY else ""
_B   = "\033[1m"  if _TTY else ""
_D   = "\033[2m"  if _TTY else ""
_X   = "\033[0m"  if _TTY else ""
_BG_R= "\033[41m" if _TTY else ""


def _print_guard_result(result: GuardResult, source: str = "LOCAL") -> None:
    if result.decision == GuardDecision.BLOCK:
        icon, clr = f"{_BG_R}{_B} 🛑 BLOCKED {_X}", _R
    elif result.decision == GuardDecision.WARN:
        icon, clr = f"{_Y}{_B}⚠️  WARNING{_X}", _Y
    else:
        icon, clr = f"{_G}✅ ALLOWED{_X}", _G

    print(f"\n  {icon}  {_B}[{result.guard_type.upper()} GUARD]{_X}  {_D}({source}){_X}")
    print(f"  {clr}├─ Decision : {result.decision.value}{_X}")
    print(f"  {clr}├─ Risk     : {result.risk_score:.0f}/100{_X}")
    trunc = result.action[:120] + ("..." if len(result.action) > 120 else "")
    print(f"  {clr}├─ Action   : {trunc}{_X}")
    print(f"  {clr}├─ Reason   : {result.reason}{_X}")
    if result.matched_rules:
        print(f"  {clr}└─ Rules    : {', '.join(result.matched_rules)}{_X}")
    print()


def _print_fast_pass(guard_type: str, action: str, elapsed_us: float) -> None:
    trunc = action[:120] + ("..." if len(action) > 120 else "")
    print(f"\n  {_G}⚡ FAST PASS{_X}  {_B}[{guard_type.upper()} GUARD]{_X}  {_D}(client · {elapsed_us:.1f}μs){_X}")
    print(f"  {_G}├─ Decision : ALLOW{_X}")
    print(f"  {_G}├─ Action   : {trunc}{_X}")
    print(f"  {_G}└─ Reason   : No suspicious keywords — passed locally{_X}\n")


class ExecutionInterceptor:
    """
    Central interceptor routing actions to the appropriate guard.

    Modes:
        enforce — Full local regex guards (all 60+ rules)
        audit   — Same as enforce but BLOCK → WARN
        hybrid  — LightGuard locally, suspicious → server, fallback to local

    Usage:
        # Production (recommended)
        interceptor = ExecutionInterceptor(
            mode="hybrid",
            backend_url="http://127.0.0.1:8000",
        )

        # Full local (no server dependency)
        interceptor = ExecutionInterceptor(mode="enforce")

        result = interceptor.check_shell("rm -rf /")
        result = interceptor.check_database("DROP TABLE users;")
        result = interceptor.check_api("POST https://webhook.site/steal")
    """

    def __init__(
        self,
        mode: str = "enforce",
        backend_url: Optional[str] = None,
        allowed_domains: Optional[List[str]] = None,
        blocked_domains: Optional[List[str]] = None,
        db_read_only: bool = False,
        verbose: bool = True,
        agent_id: Optional[str] = None,
    ):
        self.mode = mode
        self.verbose = verbose

        # Full local guards (used in enforce/audit modes, and as hybrid fallback)
        self.shell_guard = ShellGuard(mode=mode)
        self.database_guard = DatabaseGuard(mode=mode, read_only=db_read_only)
        self.api_guard = APIGuard(mode=mode, allowed_domains=allowed_domains, blocked_domains=blocked_domains)

        # Hybrid components (only initialized in hybrid mode)
        self._light_guard: Optional[LightGuard] = None
        self._server_guard: Optional[ServerGuard] = None

        if mode == "hybrid":
            self._light_guard = LightGuard()
            if backend_url:
                self._server_guard = ServerGuard(
                    backend_url=backend_url,
                    agent_id=agent_id,
                )

        self._audit_log: List[GuardResult] = []

    # ── Core check methods ────────────────────────────────────────────

    def check_shell(self, command: str, context: Optional[Dict] = None) -> GuardResult:
        if self.mode == "hybrid":
            return self._hybrid_check("shell", command, context)
        result = self.shell_guard.check(command, context)
        self._audit_log.append(result)
        if self.verbose:
            _print_guard_result(result, "LOCAL")
        return result

    def check_database(self, query: str, context: Optional[Dict] = None) -> GuardResult:
        if self.mode == "hybrid":
            return self._hybrid_check("database", query, context)
        result = self.database_guard.check(query, context)
        self._audit_log.append(result)
        if self.verbose:
            _print_guard_result(result, "LOCAL")
        return result

    def check_api(self, request: str, context: Optional[Dict] = None) -> GuardResult:
        if self.mode == "hybrid":
            return self._hybrid_check("api", request, context)
        result = self.api_guard.check(request, context)
        self._audit_log.append(result)
        if self.verbose:
            _print_guard_result(result, "LOCAL")
        return result

    # ── Hybrid path ───────────────────────────────────────────────────

    def _hybrid_check(self, guard_type: str, action: str, context: Optional[Dict] = None) -> GuardResult:
        """
        The hybrid flow:
          1. LightGuard: sub-μs keyword check
          2. If clean → ALLOW immediately (the 99% path)
          3. If suspicious → send to server for full validation
          4. If server unreachable → fall back to local full guards
        """
        assert self._light_guard is not None

        # Step 1: Light check
        if guard_type == "shell":
            light_result = self._light_guard.check_shell(action)
        elif guard_type == "database":
            light_result = self._light_guard.check_sql(action)
        else:
            light_result = self._light_guard.check_api(action)

        # Step 2: Fast pass — 99% of actions go here
        if not light_result.is_suspicious:
            result = GuardResult(
                decision=GuardDecision.ALLOW,
                guard_type=guard_type,
                action=action,
                reason="No suspicious keywords — passed locally",
                risk_score=0.0,
                matched_rules=[],
            )
            self._audit_log.append(result)
            if self.verbose:
                _print_fast_pass(guard_type, action, light_result.elapsed_us)
            return result

        # Step 3: Suspicious — send to server
        if self.verbose:
            kws = ", ".join(light_result.matched_keywords[:5])
            print(f"\n  {_Y}🔍 SUSPICIOUS{_X}  {_B}[{guard_type.upper()} GUARD]{_X}  {_D}(keywords: {kws}){_X}")
            print(f"  {_Y}   → Sending to server for full validation...{_X}")

        if self._server_guard:
            result = self._server_guard.validate(guard_type, action, context)
            # If server returned a real answer (not a fallback WARN from connection error)
            if "server_unreachable" not in result.matched_rules:
                self._audit_log.append(result)
                if self.verbose:
                    _print_guard_result(result, "SERVER")
                # Report to backend for audit
                self._server_guard.report(result)
                return result
            # Server unreachable — fall through to local

        # Step 4: Fallback — use full local guards
        if self.verbose:
            print(f"  {_Y}   ⚠ Server unreachable — falling back to local guards{_X}")

        local_guard = {
            "shell": self.shell_guard,
            "database": self.database_guard,
            "api": self.api_guard,
        }[guard_type]

        result = local_guard.check(action, context)
        self._audit_log.append(result)
        if self.verbose:
            _print_guard_result(result, "LOCAL FALLBACK")
        return result

    # ── Decorators ────────────────────────────────────────────────────

    def guard_function(self, guard_type: str = "shell") -> Callable:
        """Decorator: guards first arg as shell command / SQL query / API request."""
        check_fn = {"shell": self.check_shell, "database": self.check_database, "api": self.check_api}[guard_type]

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(action: str, *args: Any, **kwargs: Any) -> Any:
                result = check_fn(action)
                if result.decision == GuardDecision.BLOCK:
                    raise PermissionError(
                        f"[Scouter {guard_type.title()}Guard] BLOCKED: {result.reason}\n"
                        f"  Action: {action}\n  Risk: {result.risk_score}/100"
                    )
                return func(action, *args, **kwargs)
            return wrapper
        return decorator

    # ── Audit & Stats ─────────────────────────────────────────────────

    @property
    def audit_log(self) -> List[Dict]:
        return [
            {"guard_type": r.guard_type, "decision": r.decision.value,
             "action_hash": r.action_hash, "risk_score": r.risk_score,
             "reason": r.reason, "matched_rules": r.matched_rules}
            for r in self._audit_log
        ]

    @property
    def stats(self) -> Dict[str, Any]:
        base = {
            "shell": self.shell_guard.stats,
            "database": self.database_guard.stats,
            "api": self.api_guard.stats,
        }
        if self._light_guard:
            base["light_guard"] = self._light_guard.stats
        if self._server_guard:
            base["server_guard"] = self._server_guard.stats
        return base

    def print_summary(self) -> None:
        total = len(self._audit_log)
        blocked = sum(1 for r in self._audit_log if r.decision == GuardDecision.BLOCK)
        warned  = sum(1 for r in self._audit_log if r.decision == GuardDecision.WARN)
        allowed = sum(1 for r in self._audit_log if r.decision == GuardDecision.ALLOW)

        print(f"\n{'═' * 60}")
        print(f"  {_B}🔒 Scouter Execution Guard Summary{_X}")
        print(f"{'═' * 60}")
        print(f"  Mode          : {self.mode.upper()}")
        print(f"  Total checks  : {total}")
        print(f"  {_R}Blocked       : {blocked}{_X}")
        print(f"  {_Y}Warned        : {warned}{_X}")
        print(f"  {_G}Allowed       : {allowed}{_X}")

        if self.mode == "hybrid" and self._light_guard:
            lg = self._light_guard.stats
            print(f"\n  {_C}── LightGuard (client-side) ──{_X}")
            print(f"  Total checks      : {lg['total_checks']}")
            print(f"  {_G}Fast-passed (99%%) : {lg['fast_passed']}{_X}")
            print(f"  {_Y}Flagged → server  : {lg['flagged_to_server']}{_X}")
            print(f"  Pass rate         : {lg['pass_rate_pct']:.1f}%%")

        if self.mode == "hybrid" and self._server_guard:
            sg = self._server_guard.stats
            print(f"\n  {_C}── ServerGuard (server-side) ──{_X}")
            print(f"  Server calls      : {sg['server_calls']}")
            print(f"  {_R}Blocks            : {sg['server_blocks']}{_X}")
            print(f"  {_Y}Warns             : {sg['server_warns']}{_X}")
            print(f"  {_G}Allows            : {sg['server_allows']}{_X}")
            print(f"  Errors            : {sg['server_errors']}")
            print(f"  Avg latency       : {sg['avg_latency_ms']:.1f} ms")

        for gt in ("shell", "database", "api"):
            s = {"blocked": 0, "warned": 0, "allowed": 0}
            if self.mode != "hybrid":
                s = getattr(self, f"{gt}_guard").stats
            t = sum(s.values())
            if t > 0:
                print(f"    {gt:10s}: {_R}{s['blocked']} blocked{_X}  {_Y}{s['warned']} warned{_X}  {_G}{s['allowed']} allowed{_X}")

        print(f"{'═' * 60}\n")
