# Scouter SDK

**Runtime Semantic Authorization for AI Agents.**

Scouter wraps your AI agent clients to intercept, evaluate, and govern every action before it executes — stopping rogue tool calls, prompt injections, and policy violations in real time. Go to, get API Key : [Scouter](https://scouter.intellectmachines.com/ui/login.html)

[![PyPI](https://img.shields.io/pypi/v/scouter-ai)](https://pypi.org/project/scouter-ai/)
[![npm](https://img.shields.io/npm/v/@scouter-ai/node)](https://www.npmjs.com/package/@scouter-ai/node)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## Packages

| Package | Language | Description |
|---------|----------|-------------|
| [`python/`](./python) | Python 3.10+ | Python SDK — OpenAI, LangChain, CrewAI, AutoGen, PhiData |
| [`node/`](./node) | Node.js 18+ | TypeScript/JS SDK — OpenAI, Vercel AI SDK |

---

## Quick Start (Python)

```bash
pip install scouter-ai
```

```python
from scouter.client import ScouterClient
from scouter.integrations.openai import wrap_openai
from openai import OpenAI

# 1. Init Scouter
scouter = ScouterClient(
    # backend_url defaults to the Scouter cloud endpoint
    api_key="your-api-key",
    mode="enforce",   # audit | enforce
)

# 2. Register agent intent (what it's allowed / not allowed to do)
intent = scouter.register_intent(
    agent_id="support-bot",
    natural_language="Answer customer questions about orders and products",
    permitted_actions=["lookup_order", "search_knowledge_base"],
    excluded_actions=["delete_order", "modify_payment"],
)

# 3. Wrap your OpenAI client — that's it
client = wrap_openai(OpenAI(api_key="..."), scouter=scouter, intent_id=intent.intent_id)

# 4. Use normally — Scouter governs every call transparently
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "What's my order status for ORD-123?"}],
)
```

---

## Quick Start (Node / TypeScript)

```bash
npm install @scouter-ai/node
```

```typescript
import { ScouterClient } from "@scouter-ai/node";
import { wrapOpenAI } from "@scouter-ai/node/integrations/openai";
import OpenAI from "openai";

const scouter = new ScouterClient({
  // backendUrl defaults to the Scouter cloud endpoint
  apiKey: "your-api-key",
  mode: "enforce",
});

const intent = await scouter.registerIntent({
  agentId: "support-bot",
  naturalLanguage: "Answer customer support questions",
  permittedActions: ["lookup_order", "search_kb"],
  excludedActions: ["delete_data"],
});

const client = wrapOpenAI(new OpenAI(), { scouter, intentId: intent.intentId });

const response = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Check my order" }],
});
```

---

## What Scouter Does

```
User Prompt
    │
    ▼
[Action Triage Classifier]
    │ SKIP (safe, fast-pass)   SCAN (needs evaluation)
    │                               │
    │                               ▼
    │                    [Consequence Engine]
    │                               │
    │              PASS_THROUGH   FLAG   ESCALATE   HARD_STOP
    │
    ▼
[Execution Guards]  ← ShellGuard · DatabaseGuard · APIGuard
    │
    ▼
  ALLOW / BLOCK / WARN
```

### Guards

| Guard | Catches |
|-------|---------|
| `ShellGuard` | `rm -rf`, `chmod 777`, reading `/etc/shadow`, etc. |
| `DatabaseGuard` | `DROP TABLE`, `DELETE` without `WHERE`, SQL injection |
| `APIGuard` | Credentials in URLs, PUT to `/secrets`, data exfiltration |

---

## Supported Frameworks

**Python:** OpenAI · LangChain · CrewAI · AutoGen · PhiData

**Node:** OpenAI · Vercel AI SDK

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
SCOUTER_BACKEND_URL=[https://scouter.intellectmachines.com]
SCOUTER_API_KEY=your-api-key-here
```

Get your API key from the [Scouter Dashboard](https://scouter.intellectmachines.com/ui/login.html).

---

## Examples

- [`python/examples/openai_chatbot.py`](python/examples/openai_chatbot.py) — Full chatbot with tool calls and governance
- [`python/examples/openai_example.py`](python/examples/openai_example.py) — Minimal OpenAI integration
- [`python/examples/guard_demo.py`](python/examples/guard_demo.py) — Execution guard demonstrations
- [`python/examples/test_deployed.py`](python/examples/test_deployed.py) — Integration test suite

---

## Development

### Python

```bash
cd python
pip install -e ".[dev]"
pytest tests/
```

### Node

```bash
cd node
npm install
npm run build
npm test
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [IntellectMachines](https://github.com/IntellectMachines).
