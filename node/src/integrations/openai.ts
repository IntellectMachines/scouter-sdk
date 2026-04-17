/**
 * OpenAI integration — wraps openai.chat.completions.create with Scouter instrumentation.
 * Mirrors sdk/python/scouter/integrations/openai.py
 *
 * Intercepts tool calls, runs them through ActionTriageClassifier + guards,
 * evaluates via ConsequenceEngine, and sends trace spans to the backend.
 */

import type { ScouterClient } from "../client.js";
import { TriageVerdict } from "../models.js";

// ── OpenAI type interfaces (avoids `any` dependency on openai package) ──

/** Minimal interface for an OpenAI chat message. */
interface ChatMessage {
  role: string;
  content?: string | null;
  tool_calls?: ToolCall[] | null;
}

/** Minimal interface for an OpenAI tool call. */
interface ToolCall {
  id?: string;
  type?: string;
  function?: {
    name?: string;
    arguments?: string;
  };
}

/** Minimal interface for an OpenAI chat completion choice. */
interface ChatChoice {
  index?: number;
  message?: ChatMessage;
  finish_reason?: string;
}

/** Minimal interface for an OpenAI chat completion response. */
interface ChatCompletionResponse {
  id?: string;
  choices?: ChatChoice[];
  model?: string;
  [key: string]: unknown;
}

/** Minimal interface for the params passed to chat.completions.create. */
interface CreateParams {
  model?: string;
  messages?: ChatMessage[];
  tools?: ToolDefinition[] | null;
  [key: string]: unknown;
}

/** Minimal interface for an OpenAI tool definition. */
interface ToolDefinition {
  type?: string;
  function?: {
    name?: string;
    description?: string;
    parameters?: Record<string, unknown>;
  };
}

/** Minimal interface for the OpenAI client shape we wrap. */
interface OpenAILike {
  chat: {
    completions: {
      create: (...args: unknown[]) => Promise<ChatCompletionResponse>;
    };
  };
  [key: string]: unknown;
}

function debugLog(context: string, error: unknown): void {
  if (typeof process !== "undefined" && process.env?.SCOUTER_DEBUG) {
    console.debug(`[scouter] ${context}:`, error);
  }
}

/**
 * Wrap an OpenAI client instance with Scouter instrumentation.
 *
 * All `chat.completions.create` calls are intercepted: tool calls are triaged,
 * evaluated, and audited. The original response is returned untouched.
 */
export function wrapOpenAI<T extends OpenAILike>(
  openaiClient: T,
  scouter: ScouterClient,
  opts?: { intentId?: string },
): T {
  const intent = opts?.intentId
    ? scouter.registry.get(opts.intentId)
    : undefined;
  const intentId = opts?.intentId;

  const originalCreate = openaiClient.chat.completions.create.bind(
    openaiClient.chat.completions,
  );

  openaiClient.chat.completions.create = async function (
    ...args: unknown[]
  ): Promise<ChatCompletionResponse> {
    const params = (args[0] ?? {}) as CreateParams;
    const model = params.model ?? "unknown";
    const tools = params.tools ?? null;

    // 1. Triage the latest user prompt
    const lastUserMsg = getLastUserMessage(params.messages ?? []);
    if (lastUserMsg && scouter.backend) {
      const promptTriage = scouter.classifier.classifyPrompt(lastUserMsg);
      if (promptTriage.verdict === TriageVerdict.SCAN) {
        // Fire-and-forget: send to backend for ML analysis
        scouter.backend.analyzePrompt(lastUserMsg, intentId).catch((e: unknown) => {
          debugLog("analyzePrompt", e);
        });
      }
    }

    // Send request span (fire-and-forget)
    sendSpan(scouter, "request", {
      model,
      tools: toolNames(tools),
    }, intentId);

    // 2. Execute the real OpenAI call
    const response = await originalCreate(...args);

    // 3. Capture the response
    const choice = response.choices?.[0];
    const message = choice?.message;
    const content = message?.content ?? null;
    const toolCalls = message?.tool_calls ?? null;

    // Send response span
    const tcData = (toolCalls ?? []).map((tc: ToolCall) => ({
      name: tc?.function?.name ?? "?",
      arguments: tc?.function?.arguments ?? "",
    }));
    sendSpan(scouter, "response", {
      content,
      tool_calls: tcData,
      tools_available: !!tools,
      finish_reason: choice?.finish_reason,
    }, intentId);

    // 4. Triage + evaluate each tool call
    if (toolCalls) {
      for (const tc of toolCalls) {
        const fnName = tc?.function?.name ?? "unknown";
        const fnArgs = tc?.function?.arguments ?? "";

        const triage = scouter.classifier.classifyToolCall(fnName, fnArgs);

        if (triage.verdict === TriageVerdict.SKIP) {
          sendSpan(scouter, "tool_call", {
            tool_name: fnName, arguments: fnArgs, triage: "SKIP",
          }, intentId);
          continue;
        }

        // SCAN path: full evaluation
        const actionDict = {
          action_type: fnName,
          target_system: triage.category,
          payload_summary: fnArgs.slice(0, 200),
          delegation_depth: 0,
        };

        sendSpan(scouter, "tool_call", {
          tool_name: fnName, arguments: fnArgs, triage: "SCAN",
          triage_category: triage.category,
        }, intentId);

        // Run through execution guards
        guardCheck(scouter, fnName, fnArgs, triage.category);

        // Evaluate via backend or local engine
        if (scouter.backend && intentId) {
          scouter.backend.evaluate(actionDict, intentId, scouter.traceId, model).catch((e: unknown) => {
            debugLog("evaluate", e);
          });
        } else {
          scouter.engine.evaluate(
            {
              actionType: fnName,
              targetSystem: triage.category,
              payloadSummary: fnArgs.slice(0, 200),
              delegationDepth: 0,
            },
            intent,
          );
        }
      }
    } else if (content) {
      // Text completion — triage
      const triage = scouter.classifier.classifyCompletion(content);
      if (triage.verdict === TriageVerdict.SCAN && scouter.backend && intentId) {
        const actionDict = {
          action_type: "llm:completion",
          target_system: triage.category,
          payload_summary: content.slice(0, 200),
          delegation_depth: 0,
        };
        scouter.backend.evaluate(actionDict, intentId, scouter.traceId, model).catch((e: unknown) => {
          debugLog("evaluate completion", e);
        });
      }
    }

    // 5. Trigger behavioral analysis (fire-and-forget)
    if (scouter.backend) {
      setTimeout(() => {
        scouter.backend!.analyzeTrace(scouter.traceId).catch((e: unknown) => {
          debugLog("analyzeTrace", e);
        });
      }, 300);
    }

    // 6. Return original response untouched
    return response;
  };

  return openaiClient;
}

// ── Helpers ──────────────────────────────────────────────────────────

function guardCheck(
  scouter: ScouterClient,
  _toolName: string,
  args: string,
  category: string,
): void {
  if (!scouter.interceptor) return;

  const actionStr = `${_toolName} ${args}`;

  if (category === "system") {
    scouter.interceptor.checkShell(actionStr);
  } else if (category === "database") {
    scouter.interceptor.checkDatabase(actionStr);
  } else if (["api", "third_party_api", "cloud", "financial"].includes(category)) {
    scouter.interceptor.checkApi(actionStr);
  } else {
    const result = scouter.interceptor.checkShell(actionStr);
    if (result.decision === "ALLOW") {
      scouter.interceptor.checkApi(actionStr);
    }
  }
}

function sendSpan(
  scouter: ScouterClient,
  spanType: string,
  data: Record<string, unknown>,
  intentId?: string,
): void {
  if (!scouter.backend) return;
  scouter.backend.ingestSpan(scouter.traceId, spanType, data, "", intentId ?? "").catch((e: unknown) => {
    debugLog("ingestSpan", e);
  });
}

function getLastUserMessage(messages: ChatMessage[]): string | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg?.role === "user" && typeof msg.content === "string" && msg.content.trim()) {
      return msg.content.trim();
    }
  }
  return null;
}

function toolNames(tools: ToolDefinition[] | null): string[] {
  if (!tools) return [];
  return tools.map((t: ToolDefinition) => t?.function?.name ?? "?");
}
