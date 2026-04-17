"""
Consequence Engine — Score-based, Audit Mode (Phase 1).

Implements the Decision Matrix from STD §6:
  - Irreversibility scoring via a static action-type map.
  - Keyword-based alignment scoring (vector embeddings deferred to Phase 2).
  - Always returns AUDIT_PASS; logs the *calculated* decision.
"""

from __future__ import annotations

from typing import Optional

from scouter.models import (
    ActionProposal,
    ActualExecution,
    Decision,
    Evaluation,
    GovernanceDecision,
    IntentDeclaration,
)

# STD §3.2 — static irreversibility map
_IRREVERSIBILITY: dict[str, float] = {
    "read": 0.05,
    "list": 0.05,
    "search": 0.05,
    "get": 0.05,
    "write": 0.35,
    "create": 0.40,
    "update": 0.45,
    "send": 0.70,
    "send:external": 0.75,
    "execute": 0.65,
    "delete": 0.95,
    "drop": 0.95,
}

# Pre-sorted once at module load (longest key first for correct prefix matching)
_SORTED_IRREV_KEYS: list[tuple[str, float]] = sorted(
    _IRREVERSIBILITY.items(), key=lambda kv: len(kv[0]), reverse=True
)


def _irreversibility_score(action_type: str) -> float:
    """Compute irreversibility from the action type prefix."""
    lower = action_type.lower()
    for key, score in _SORTED_IRREV_KEYS:
        if lower.startswith(key) or key in lower:
            return score
    return 0.50  # unknown actions get a moderate score


def _keyword_alignment(action: ActionProposal, intent: IntentDeclaration) -> float:
    """
    Phase 1 keyword-based alignment proxy.
    Checks how much of the action description overlaps with the intent's
    permitted actions and natural language.  Returns 0.0 – 1.0.
    """
    if not intent:
        return 0.0

    action_text = f"{action.action_type} {action.target_system} {action.payload_summary}".lower()
    action_parts = set(action_text.replace(":", " ").replace("_", " ").split())

    # Boost if action_type matches a permitted action pattern
    for perm in intent.permitted_actions:
        perm_lower = perm.lower()
        perm_parts = set(perm_lower.replace(":", " ").replace("_", " ").split())
        if perm_lower in action_text or perm_parts.issubset(action_parts):
            return 0.90

    # Penalise if action matches an excluded pattern
    for excl in intent.excluded_actions:
        excl_lower = excl.lower()
        excl_parts = set(excl_lower.replace(":", " ").replace("_", " ").split())
        if excl_lower in action_text or excl_parts.issubset(action_parts):
            return 0.10

    # Fall back to token overlap with natural language intent
    intent_tokens = set(intent.natural_language.lower().split())
    action_tokens = set(action_text.split())
    if not intent_tokens:
        return 0.50
    overlap = len(intent_tokens & action_tokens) / len(intent_tokens)
    return round(min(overlap + 0.30, 1.0), 2)


class ConsequenceEngine:
    """Audit-mode consequence evaluator."""

    def __init__(self, mode: str = "audit") -> None:
        self.mode = mode

    def evaluate(
        self,
        action: ActionProposal,
        intent: Optional[IntentDeclaration] = None,
    ) -> GovernanceDecision:
        irrev = _irreversibility_score(action.action_type)
        alignment = _keyword_alignment(action, intent) if intent else 0.50

        # STD §6.1 — delegation depth penalty
        penalty = min(0.4, action.delegation_depth * 0.08)
        final_score = alignment * (1.0 - penalty)

        # STD §6.2 — decision matrix
        calculated = self._decide(irrev, final_score)

        rationale_parts = []
        if irrev > 0.6:
            rationale_parts.append("High irreversibility")
        if final_score < 0.6:
            rationale_parts.append("Low intent alignment")
        if not rationale_parts:
            rationale_parts.append("Action within expected parameters")

        evaluation = Evaluation(
            irreversibility_score=round(irrev, 2),
            alignment_score=round(final_score, 2),
            calculated_decision=calculated,
            actual_execution=ActualExecution.AUDIT_PASS,
            rationale="; ".join(rationale_parts) + ".",
        )

        return GovernanceDecision(
            intent_id=intent.intent_id if intent else "",
            action=action,
            evaluation=evaluation,
        )

    @staticmethod
    def _decide(irreversibility: float, alignment: float) -> Decision:
        if irreversibility > 0.8:
            return Decision.ESCALATE
        if irreversibility > 0.6 and alignment < 0.6:
            return Decision.HARD_STOP
        if irreversibility < 0.3 and alignment > 0.7:
            return Decision.PASS_THROUGH
        if alignment < 0.5:
            return Decision.FLAG
        return Decision.PASS_THROUGH
