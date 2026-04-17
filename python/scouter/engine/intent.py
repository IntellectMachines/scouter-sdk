"""
Intent Registry Service — Rule-based (Phase 1).

Stores agent intent declarations in-memory and provides lookup
for the Consequence Engine. Vector embeddings are deferred to Phase 2;
this implementation uses keyword-based matching.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from scouter.models import IntentDeclaration, Principal


class IntentRegistry:
    """In-memory, rule-based intent store."""

    def __init__(self) -> None:
        self._store: Dict[str, IntentDeclaration] = {}

    def register(
        self,
        agent_id: str,
        intent: str,
        permitted_actions: Optional[List[str]] = None,
        excluded_actions: Optional[List[str]] = None,
        permitted_domains: Optional[List[str]] = None,
        principal_chain: Optional[List[Dict[str, str]]] = None,
        version: str = "1.0",
    ) -> IntentDeclaration:
        """Register a new intent declaration for an agent."""

        actions = list(permitted_actions or [])
        if permitted_domains:
            for domain in permitted_domains:
                actions.append(f"read:{domain}")
                actions.append(f"write:{domain}")

        principals = []
        if principal_chain:
            principals = [Principal(**p) for p in principal_chain]

        declaration = IntentDeclaration(
            agent_id=agent_id,
            natural_language=intent,
            permitted_actions=actions,
            excluded_actions=list(excluded_actions or []),
            principal_chain=principals,
            version=version,
        )

        self._store[declaration.intent_id] = declaration
        return declaration

    def get(self, intent_id: str) -> Optional[IntentDeclaration]:
        return self._store.get(intent_id)

    def get_by_agent(self, agent_id: str) -> Optional[IntentDeclaration]:
        for decl in self._store.values():
            if decl.agent_id == agent_id:
                return decl
        return None
