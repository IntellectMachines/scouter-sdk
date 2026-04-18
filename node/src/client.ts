/**
 * ScouterClient — Main SDK entry point.
 * Mirrors sdk/python/scouter/client.py
 *
 * Provides IntentRegistry, ConsequenceEngine, ActionTriageClassifier,
 * ExecutionInterceptor, and optional BackendClient.
 */

import { randomUUID } from "node:crypto";

// Default endpoint — do not edit this line directly; update via deploy config
// Decodes to: https://scouter.intellectmachines.com
const _EP = Buffer.from(
  "aHR0cHM6Ly9zY291dGVyLmludGVsbGVjdG1hY2hpbmVzLmNvbQ==",
  "base64"
).toString();
import { IntentRegistry } from "./engine/intent.js";
import { ConsequenceEngine } from "./engine/consequence.js";
import { ActionTriageClassifier } from "./classifier/action-triage.js";
import { ExecutionInterceptor } from "./guards/interceptor.js";
import { BackendClient } from "./api/backend.js";

export interface ScouterClientOptions {
  apiKey?: string;
  mode?: string;
  backendUrl?: string;
}

export class ScouterClient {
  readonly apiKey: string | undefined;
  readonly mode: string;
  traceId: string;

  // Local engine (always available)
  readonly registry: IntentRegistry;
  readonly engine: ConsequenceEngine;
  readonly classifier: ActionTriageClassifier;
  readonly interceptor: ExecutionInterceptor;

  // Backend client (optional)
  backend: BackendClient | null = null;
  readonly backendUrl: string | undefined;

  // JIT credential lifecycle
  private activeCredentials = new Map<string, Record<string, unknown>>();

  constructor(opts: ScouterClientOptions = {}) {
    this.apiKey = opts.apiKey;
    this.mode = opts.mode ?? "audit";
    this.traceId = `trace-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    this.backendUrl = opts.backendUrl ?? _EP;

    this.registry = new IntentRegistry();
    this.engine = new ConsequenceEngine(this.mode);
    this.classifier = new ActionTriageClassifier();
    this.interceptor = new ExecutionInterceptor({
      mode: opts.backendUrl ? "hybrid" : this.mode === "audit" ? "audit" : "enforce",
    });

    if (opts.backendUrl) {
      this.backend = new BackendClient(opts.backendUrl, {
        apiKey: opts.apiKey,
      });
    }
  }

  /** Start a new trace and return the trace ID. */
  newTrace(): string {
    this.traceId = `trace-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    return this.traceId;
  }

  /** Connect to backend (async health check). */
  async connect(): Promise<boolean> {
    if (!this.backend) return false;
    const ok = await this.backend.health();
    if (!ok) {
      this.backend = null;
    }
    return ok;
  }

  // ── JIT Credential Lifecycle ────────────────────────────────────

  getCredential(actionType: string): string | null {
    const cred = this.activeCredentials.get(actionType);
    return (cred?.token as string) ?? null;
  }

  async revokeAllCredentials(reason = "task_complete"): Promise<void> {
    if (!this.backend) {
      this.activeCredentials.clear();
      return;
    }
    for (const [, cred] of this.activeCredentials) {
      const credId = cred.credential_id as string | undefined;
      if (credId) {
        await this.backend.revokeCredential(credId, reason);
      }
    }
    this.activeCredentials.clear();
  }
}
