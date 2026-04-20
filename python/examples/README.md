# Scouter Python Examples

Progressive, copy-pasteable examples for setting up the Scouter SDK in your
project. Start at the top — each example builds on the previous one.

| # | File | What it shows | Needs |
|---|------|---------------|-------|
| 01 | [`01_quickstart.py`](01_quickstart.py) | Local-only setup: client + intent + one evaluation. | nothing |
| 02 | [`02_guards_inline.py`](02_guards_inline.py) | Drop `ShellGuard` / `DatabaseGuard` / `APIGuard` into your own code paths. | nothing |
| 03 | [`03_openai_governance.py`](03_openai_governance.py) | Govern every OpenAI call with the one-line `wrap_openai()` integration. | `OPENAI_API_KEY` |
| 04 | [`04_connect_backend.py`](04_connect_backend.py) | Connect to the Scouter backend, register intents server-side, and use task-scoped JIT credentials. | `SCOUTER_BACKEND_URL`, `SCOUTER_API_KEY` |

## Setup once

```bash
cd python
pip install -e ".[dev]"
cp .env.example .env   # then fill in any keys you need
```

## Deeper / framework-specific demos

- [`openai_chatbot.py`](openai_chatbot.py) — full agentic chatbot with tool calls and live governance output.
- [`openai_example.py`](openai_example.py) — minimal OpenRouter agent loop with file-ops tools.
- [`guard_demo.py`](guard_demo.py) — exhaustive guard rule walkthrough (red-team scenarios).
- [`hybrid_guard_demo.py`](hybrid_guard_demo.py) — local guards + backend behavioral analysis combined.
