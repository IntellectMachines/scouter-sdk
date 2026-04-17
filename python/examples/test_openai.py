"""
Minimal OpenRouter connectivity test.

Sends a single chat completion request via OpenRouter to verify
the API key and network connection are working.

Prerequisites:
  pip install openai python-dotenv
  Add your key to sdk/python/.env:  OPENROUTER_API_KEY=sk-or-...

Run:
  python examples/test_openai.py
"""

import os
import sys

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def main() -> None:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key or api_key == "your-openrouter-api-key-here":
        print("\n  ERROR: Set OPENROUTER_API_KEY in sdk/python/.env first.\n")
        sys.exit(1)

    from openai import OpenAI

    client = OpenAI(api_key=api_key, base_url=OPENROUTER_BASE_URL)

    print("\n  Sending test request to OpenRouter...")

    response = client.chat.completions.create(
        model="openai/gpt-4o-mini",
        messages=[
            {"role": "user", "content": "Reply with exactly: SCOUTER_OK"}
        ],
        max_tokens=10,
    )

    reply = response.choices[0].message.content.strip()
    model = response.model
    usage = response.usage

    print(f"  Model:    {model}")
    print(f"  Reply:    {reply}")
    print(f"  Tokens:   prompt={usage.prompt_tokens}  completion={usage.completion_tokens}  total={usage.total_tokens}")

    if "SCOUTER_OK" in reply:
        print("\n  ✓ OpenRouter connection is working.\n")
    else:
        print(f"\n  ⚠ Unexpected reply (connection works, but response differs): {reply}\n")


if __name__ == "__main__":
    main()
