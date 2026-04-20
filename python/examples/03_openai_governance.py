"""
03 — OpenAI Integration: govern every model call with one line.

What this shows
---------------
`wrap_openai(client, scouter, intent_id=...)` patches an
`openai.OpenAI()` instance so that every `chat.completions.create`
call is transparently:
  - classified by the Action Triage Classifier (fast path for safe text),
  - checked against the registered intent,
  - intercepted by the execution guards if a tool_call is dangerous.

Your downstream code is unchanged — the wrapper returns the original
response object.

Setup
-----
    cp .env.example .env       # then fill in OPENAI_API_KEY
    pip install openai python-dotenv

Run
---
    python examples/03_openai_governance.py
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openai import OpenAI

from scouter import ScouterClient
from scouter.integrations.openai import wrap_openai


def main() -> None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Set OPENAI_API_KEY in python/.env to run this example.")
        sys.exit(0)

    # 1. Configure Scouter (local-only is fine to start).
    scouter = ScouterClient(mode="enforce", verbose=True, backend_url=None)
    intent = scouter.registry.register(
        agent_id="support-bot",
        intent="Help customers track orders and answer product FAQs.",
        permitted_actions=["lookup_order", "search_knowledge_base"],
        excluded_actions=["exec_shell", "delete_order", "modify_payment"],
    )

    # 2. Wrap the OpenAI client. That's it — every future call is governed.
    raw_client = OpenAI(api_key=api_key)
    client = wrap_openai(raw_client, scouter=scouter, intent_id=intent.intent_id)

    # 3. Use the client exactly as you would normally.
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a concise customer support bot."},
            {"role": "user", "content": "What's the status of order ORD-10002?"},
        ],
    )
    print("\nAssistant:", response.choices[0].message.content)


if __name__ == "__main__":
    main()
