"""
01 — Quickstart: Local-only Scouter setup in ~20 lines.

What this shows
---------------
The smallest possible "is Scouter installed and working?" flow:
  1. Create a ScouterClient in audit mode (no backend, no API key).
  2. Register an agent intent (its allowed / excluded actions).
  3. Ask the local Consequence Engine to evaluate a proposed action.

Run
---
    cd python
    pip install -e .
    python examples/01_quickstart.py

No API key, no network, no external services required.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scouter import ScouterClient
from scouter.models import ActionProposal


def main() -> None:
    # 1. Initialise the SDK in local audit mode.
    #    `backend_url=None` keeps everything in-process — perfect for
    #    development, unit tests, and CI.
    scouter = ScouterClient(mode="audit", verbose=True, backend_url=None)

    # 2. Declare what the agent is *supposed* to do. This is the contract
    #    every future action will be measured against.
    intent = scouter.registry.register(
        agent_id="support-bot",
        intent="Answer customer questions about orders and products.",
        permitted_actions=["lookup_order", "search_knowledge_base"],
        excluded_actions=["delete_order", "modify_payment", "exec_shell"],
    )
    print(f"\nRegistered intent: {intent.intent_id}\n")

    # 3. Evaluate two proposed actions through the local Consequence Engine.
    proposals = [
        ActionProposal(
            action_type="lookup_order",
            target_system="orders_db",
            payload_summary="order_id=ORD-10002",
        ),
        ActionProposal(
            action_type="delete_order",
            target_system="orders_db",
            payload_summary="order_id=ORD-10002",
        ),
    ]

    for proposal in proposals:
        decision = scouter.engine.evaluate(proposal, intent=intent)
        ev = decision.evaluation
        print(
            f"  {proposal.action_type:<25} "
            f"calculated={ev.calculated_decision.value:<13} "
            f"alignment={ev.alignment_score:<5} "
            f"irreversibility={ev.irreversibility_score}"
        )

    print("\nDone. Next: see 02_guards_inline.py for runtime blocking.")


if __name__ == "__main__":
    main()
