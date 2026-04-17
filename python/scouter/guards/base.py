"""
Base guard interface and shared types for execution-layer protection.
"""

from __future__ import annotations

import enum
import time
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class GuardDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"


@dataclass
class GuardResult:
    decision: GuardDecision
    guard_type: str          # "shell", "database", "api"
    action: str              # The command/query/url that was checked
    reason: str
    risk_score: float = 0.0
    matched_rules: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    action_hash: str = ""

    def __post_init__(self):
        if not self.action_hash:
            self.action_hash = hashlib.sha256(self.action.encode()).hexdigest()[:16]


class BaseGuard:
    """Abstract base for all execution guards."""

    guard_type: str = "base"

    def __init__(self, mode: str = "enforce", custom_rules: Optional[List[Dict[str, Any]]] = None):
        self.mode = mode  # "audit" = log only, "enforce" = actually block
        self.custom_rules = custom_rules or []
        self._blocked = 0
        self._warned = 0
        self._allowed = 0

    def check(self, action: str, context: Optional[Dict[str, Any]] = None) -> GuardResult:
        result = self.analyze(action, context or {})

        if result.decision == GuardDecision.BLOCK:
            self._blocked += 1
        elif result.decision == GuardDecision.WARN:
            self._warned += 1
        else:
            self._allowed += 1

        # In audit mode, downgrade BLOCK to WARN
        if self.mode == "audit" and result.decision == GuardDecision.BLOCK:
            result = GuardResult(
                decision=GuardDecision.WARN,
                guard_type=result.guard_type,
                action=result.action,
                reason=f"[AUDIT] Would block: {result.reason}",
                risk_score=result.risk_score,
                matched_rules=result.matched_rules,
            )
        return result

    def analyze(self, action: str, context: Dict[str, Any]) -> GuardResult:
        raise NotImplementedError

    @property
    def stats(self) -> Dict[str, int]:
        return {"blocked": self._blocked, "warned": self._warned, "allowed": self._allowed}
