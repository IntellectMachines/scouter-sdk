"""
04 — Connect to the Scouter backend & use task-scoped JIT credentials.

What this shows
---------------
Once you point `backend_url` at a Scouter deployment (cloud or
self-hosted), the SDK upgrades automatically:
  - Intents are persisted server-side.
  - Decisions get Ed25519-signed audit artifacts.
  - You can mint short-lived JIT credentials bound to a *task*; on
    task exit Scouter cascade-revokes every credential it issued.

Setup
-----
    cp .env.example .env
    # then set:
    #   SCOUTER_BACKEND_URL=https://scouter.intellectmachines.com
    #   SCOUTER_API_KEY=...

Run
---
    python examples/04_connect_backend.py
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scouter import ScouterClient


def main() -> None:
    backend_url = os.environ.get("SCOUTER_BACKEND_URL")
    api_key = os.environ.get("SCOUTER_API_KEY")
    if not backend_url or not api_key:
        print("Set SCOUTER_BACKEND_URL and SCOUTER_API_KEY in python/.env to run this example.")
        sys.exit(0)

    # 1. Connect. The client falls back to local mode if the backend
    #    is unreachable, so this is always safe to call.
    scouter = ScouterClient(
        api_key=api_key,
        backend_url=backend_url,
        mode="enforce",
        verbose=True,
    )

    if not scouter.backend:
        print("Backend unreachable — operating in local-only mode.")
        return

    # 2. Register the agent's intent server-side.
    intent = scouter.backend.register_intent(
        agent_id="refund-bot",
        natural_language="Process customer refund requests up to $500.",
        permitted_actions=["lookup_order", "issue_refund"],
        excluded_actions=["delete_order", "modify_payment_method"],
    )
    if not intent:
        print("Failed to register intent (check API key / network).")
        return
    intent_id = intent["intent_id"]
    print(f"\nRegistered intent {intent_id} on backend.\n")

    # 3. Open a task. Any credentials minted inside the `with` block are
    #    automatically revoked when the block exits.
    with scouter.task(intent_id=intent_id, agent_id="refund-bot",
                      description="Refund order ORD-10002") as task:
        if task.task_id is None:
            print("Backend did not return a task_id; skipping credential demo.")
            return

        cred = scouter.backend.mint_credential(
            intent_id=intent_id,
            artifact_id="demo-artifact",
            scope={"action_type": "issue_refund", "amount_max_usd": 500},
            ttl_seconds=300,
            task_id=task.task_id,
        )
        if cred:
            print(f"Minted JIT credential {cred['credential_id']} "
                  f"(expires {cred['expires_at']})")
        else:
            print("Mint refused (likely capability-escalation guard).")

    print("\nTask closed; any minted credentials have been revoked.")


if __name__ == "__main__":
    main()
