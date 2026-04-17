/**
 * BackendClient — fetch-based HTTP client for the Scouter backend REST API.
 * Mirrors sdk/python/scouter/api/backend.py (all 19 methods).
 * Falls back gracefully — returns null on connection errors.
 */

import type { RegisterIntentParams, ActionPayload, MintCredentialParams } from "../models.js";

// ── Response types ───────────────────────────────────────────────────

export interface IntentResponse {
  intent_id: string;
  agent_id: string;
  natural_language: string;
  permitted_actions: string[];
  excluded_actions: string[];
  has_embedding?: boolean;
  [key: string]: unknown;
}

export interface EvaluationResponse {
  artifact_id: string;
  timestamp: string;
  intent_id: string;
  action: Record<string, unknown>;
  evaluation: {
    irreversibility_score: number;
    alignment_score: number;
    calculated_decision: string;
    actual_execution: string;
    rationale: string;
  };
  signature?: string;
  public_key_id?: string;
  [key: string]: unknown;
}

export interface SpanResponse {
  span_id: string;
  trace_id: string;
  span_type: string;
  [key: string]: unknown;
}

export interface AnalyzeTraceResponse {
  trace_id: string;
  findings: Array<{
    failure_type: string;
    severity: string;
    description: string;
    [key: string]: unknown;
  }>;
  count: number;
}

export interface ArtifactVerifyResponse {
  valid: boolean;
  artifact_id?: string;
  [key: string]: unknown;
}

export interface ComplianceExportResponse {
  export_type: string;
  total_artifacts: number;
  public_key: string;
  [key: string]: unknown;
}

export interface TelemetryStatsResponse {
  total_decisions: number;
  unique_agents: number;
  decision_breakdown: Record<string, number>;
  [key: string]: unknown;
}

export interface TelemetryRecord {
  telemetry_id: string;
  agent_id: string;
  action_type: string;
  calculated_decision: string;
  [key: string]: unknown;
}

export interface AgentStatsResponse {
  total_decisions: number;
  decision_breakdown: Record<string, number>;
  [key: string]: unknown;
}

export interface PromptAnalysisResponse {
  decision: string;
  risk_score: number;
  [key: string]: unknown;
}

export interface PromptBatchResponse {
  results: PromptAnalysisResponse[];
  [key: string]: unknown;
}

export interface CredentialResponse {
  credential_id: string;
  token?: string;
  expires_at: string;
  [key: string]: unknown;
}

export interface PbacEvalResponse {
  allowed: boolean;
  policy_id?: string;
  reason?: string;
  [key: string]: unknown;
}

export interface PbacPolicyResponse {
  policy_id: string;
  intent_id: string;
  [key: string]: unknown;
}

export interface DIDResponse {
  did: string;
  status: string;
  did_document?: Record<string, unknown>;
  private_key?: string;
  [key: string]: unknown;
}

export interface DIDKeyRotateResponse {
  new_key_id: string;
  private_key: string;
  [key: string]: unknown;
}

// ── Client ───────────────────────────────────────────────────────────

export interface BackendClientOptions {
  timeout?: number;
  apiKey?: string;
}

export class BackendClient {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly headers: Record<string, string>;

  constructor(baseUrl: string, options: BackendClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeout = options.timeout ?? 5000;
    this.headers = { "Content-Type": "application/json" };
    if (options.apiKey) {
      this.headers["X-Scouter-API-Key"] = options.apiKey;
    }
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    timeoutOverride?: number,
  ): Promise<T | null> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(
        () => controller.abort(),
        timeoutOverride ?? this.timeout,
      );
      const opts: RequestInit = {
        method,
        headers: this.headers,
        signal: controller.signal,
      };
      if (body !== undefined) {
        opts.body = JSON.stringify(body);
      }
      const res = await fetch(`${this.baseUrl}${path}`, opts);
      clearTimeout(timer);
      if (!res.ok) return null;
      return (await res.json()) as T;
    } catch {
      return null;
    }
  }

  // ── Intent Registry ────────────────────────────────────────────

  async registerIntent(params: RegisterIntentParams): Promise<IntentResponse | null> {
    return this.request<IntentResponse>("POST", "/api/v1/intents", {
      agent_id: params.agentId,
      natural_language: params.naturalLanguage,
      permitted_actions: params.permittedActions,
      excluded_actions: params.excludedActions,
      principal_chain: params.principalChain ?? [],
      version: params.version ?? "1.0",
    });
  }

  async getIntent(intentId: string): Promise<IntentResponse | null> {
    return this.request<IntentResponse>("GET", `/api/v1/intents/${intentId}`);
  }

  // ── Consequence Engine ─────────────────────────────────────────

  async evaluate(
    action: ActionPayload | Record<string, unknown>,
    intentId?: string,
    traceId?: string,
    model?: string,
  ): Promise<EvaluationResponse | null> {
    const actionPayload = "actionType" in action
      ? {
          action_type: (action as ActionPayload).actionType,
          target_system: (action as ActionPayload).targetSystem,
          payload_summary: (action as ActionPayload).payloadSummary,
          delegation_depth: (action as ActionPayload).delegationDepth ?? 0,
        }
      : action;
    return this.request<EvaluationResponse>("POST", "/api/v1/engine/evaluate", {
      action: actionPayload,
      intent_id: intentId,
      trace_id: traceId,
      model,
    });
  }

  // ── Observability ──────────────────────────────────────────────

  async ingestSpan(
    traceId: string,
    spanType: string,
    data: Record<string, unknown>,
    agentId = "",
    intentId = "",
  ): Promise<SpanResponse | null> {
    return this.request<SpanResponse>("POST", "/api/v1/observability/traces", {
      trace_id: traceId,
      span_type: spanType,
      data,
      agent_id: agentId,
      intent_id: intentId,
    });
  }

  async analyzeTrace(traceId: string): Promise<AnalyzeTraceResponse | null> {
    return this.request<AnalyzeTraceResponse>("POST", `/api/v1/observability/traces/${traceId}/analyze`);
  }

  // ── Audit ──────────────────────────────────────────────────────

  async verifyArtifact(artifactId: string): Promise<ArtifactVerifyResponse | null> {
    return this.request<ArtifactVerifyResponse>("GET", `/api/v1/audit/verify/${artifactId}`);
  }

  async exportCompliance(): Promise<ComplianceExportResponse | null> {
    return this.request<ComplianceExportResponse>("GET", "/api/v1/audit/export");
  }

  // ── Health ─────────────────────────────────────────────────────

  async health(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);
      const res = await fetch(`${this.baseUrl}/health`, {
        headers: this.headers,
        signal: controller.signal,
      });
      clearTimeout(timer);
      return res.status === 200;
    } catch {
      return false;
    }
  }

  // ── Telemetry ──────────────────────────────────────────────────

  async getTelemetryStats(): Promise<TelemetryStatsResponse | null> {
    return this.request<TelemetryStatsResponse>("GET", "/api/v1/telemetry/stats");
  }

  async getAgentTelemetry(
    agentId: string,
    limit = 100,
  ): Promise<TelemetryRecord[] | null> {
    return this.request<TelemetryRecord[]>("GET", `/api/v1/telemetry/agent/${agentId}?limit=${limit}`);
  }

  async getAgentStats(agentId: string): Promise<AgentStatsResponse | null> {
    return this.request<AgentStatsResponse>("GET", `/api/v1/telemetry/agent/${agentId}/stats`);
  }

  async getTraceTelemetry(traceId: string): Promise<TelemetryRecord[] | null> {
    return this.request<TelemetryRecord[]>("GET", `/api/v1/telemetry/trace/${traceId}`);
  }

  // ── Prompt Analyzer ────────────────────────────────────────────

  async analyzePrompt(
    prompt: string,
    intentId?: string,
    agentId?: string,
  ): Promise<PromptAnalysisResponse | null> {
    return this.request<PromptAnalysisResponse>(
      "POST",
      "/api/v1/prompt/analyze",
      { prompt, intent_id: intentId, agent_id: agentId },
      120_000,
    );
  }

  async analyzePromptBatch(
    prompts: string[],
    intentId?: string,
    agentId?: string,
  ): Promise<PromptBatchResponse | null> {
    return this.request<PromptBatchResponse>(
      "POST",
      "/api/v1/prompt/analyze/batch",
      { prompts, intent_id: intentId, agent_id: agentId },
      300_000,
    );
  }

  // ── JIT Credentials ────────────────────────────────────────────

  async mintCredential(params: MintCredentialParams): Promise<CredentialResponse | null> {
    return this.request<CredentialResponse>("POST", "/api/v1/auth/credentials/mint", {
      intent_id: params.intentId,
      artifact_id: params.artifactId,
      scope: params.scope ?? {},
      ...(params.ttlSeconds ? { ttl_seconds: params.ttlSeconds } : {}),
    });
  }

  async revokeCredential(
    credentialId: string,
    reason = "task_complete",
  ): Promise<Record<string, unknown> | null> {
    return this.request("POST", "/api/v1/auth/credentials/revoke", {
      credential_id: credentialId,
      reason,
    });
  }

  async validateCredential(token: string): Promise<CredentialResponse | null> {
    return this.request<CredentialResponse>("POST", "/api/v1/auth/credentials/validate", { token });
  }

  // ── PBAC Policies ──────────────────────────────────────────────

  async evaluatePbac(
    intentId: string,
    actionType: string,
    targetSystem = "",
  ): Promise<PbacEvalResponse | null> {
    return this.request<PbacEvalResponse>("POST", "/api/v1/auth/policies/evaluate", {
      intent_id: intentId,
      action_type: actionType,
      target_system: targetSystem,
    });
  }

  async listPolicies(intentId?: string): Promise<PbacPolicyResponse[] | null> {
    const qs = intentId ? `?intent_id=${intentId}` : "";
    return this.request<PbacPolicyResponse[]>("GET", `/api/v1/auth/policies${qs}`);
  }

  // ── Agent DID Registry ────────────────────────────────────────

  async registerAgentDID(params: {
    agentId: string;
    displayName?: string;
  }): Promise<DIDResponse | null> {
    return this.request<DIDResponse>("POST", "/api/v1/dids/register", {
      agent_id: params.agentId,
      display_name: params.displayName,
    });
  }

  async resolveDID(did: string): Promise<DIDResponse | null> {
    return this.request<DIDResponse>("GET", `/api/v1/dids/${did}`);
  }

  async revokeDID(
    did: string,
    reason = "cessation",
  ): Promise<DIDResponse | null> {
    return this.request<DIDResponse>("POST", `/api/v1/dids/${did}/revoke`, { reason });
  }

  async rotateDIDKey(did: string): Promise<DIDKeyRotateResponse | null> {
    return this.request<DIDKeyRotateResponse>("POST", `/api/v1/dids/${did}/keys/rotate`);
  }
}
