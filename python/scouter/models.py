"""
Scouter data models aligned with STD §5 schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Decision(str, Enum):
    PASS_THROUGH = "PASS_THROUGH"
    FLAG = "FLAG"
    PAUSE = "PAUSE"
    HARD_STOP = "HARD_STOP"
    ESCALATE = "ESCALATE"


class ActualExecution(str, Enum):
    AUDIT_PASS = "AUDIT_PASS"
    BLOCKED = "BLOCKED"
    ESCALATE = "ESCALATE"


@dataclass
class Principal:
    user: str
    role: str


@dataclass
class IntentDeclaration:
    intent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    natural_language: str = ""
    permitted_actions: List[str] = field(default_factory=list)
    excluded_actions: List[str] = field(default_factory=list)
    principal_chain: List[Principal] = field(default_factory=list)
    version: str = "1.0"
    intent_vector: Optional[List[float]] = None

    @property
    def id(self) -> str:
        return self.intent_id


@dataclass
class ActionProposal:
    action_type: str = ""
    target_system: str = ""
    payload_summary: str = ""
    delegation_depth: int = 0


@dataclass
class Evaluation:
    irreversibility_score: float = 0.0
    alignment_score: float = 0.0
    calculated_decision: Decision = Decision.PASS_THROUGH
    actual_execution: ActualExecution = ActualExecution.AUDIT_PASS
    rationale: str = ""


@dataclass
class GovernanceDecision:
    artifact_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    intent_id: str = ""
    action: ActionProposal = field(default_factory=ActionProposal)
    evaluation: Evaluation = field(default_factory=Evaluation)


@dataclass
class BehavioralTraceSpan:
    trace_id: str = ""
    user_id: str = ""
    event_type: str = "behavioral_observation"
    failure_type: Optional[str] = None
    confidence: float = 0.0
    probable_cause: str = ""
