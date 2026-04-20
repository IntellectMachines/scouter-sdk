/**
 * ScouterClient — Main SDK entry point.
 * Mirrors sdk/python/scouter/client.py
 *
 * Provides IntentRegistry, ConsequenceEngine, ActionTriageClassifier,
 * ExecutionInterceptor, and optional BackendClient.
 */

import { randomUUID } from "node:crypto";

// Default Scouter backend endpoint. Override per-deployment via `backendUrl`
// or the SCOUTER_BACKEND_URL env var. Stored in plaintext deliberately —
// obfuscation provides no security and impedes supply-chain auditing.
const DEFAULT_BACKEND_URL = "https://scouter.intellectmachines.com";

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
    this.backendUrl = opts.backendUrl ?? DEFAULT_BACKEND_URL;

    // Refuse to transmit an API key over plaintext HTTP — credential leak risk.
    // Allow loopback for local development.
    let safeApiKey = this.apiKey;
    if (safeApiKey && this.backendUrl) {
      const u = (() => {
        try { return new URL(this.backendUrl); } catch { return null; }
      })();
      const isLoopback = u
        ? ["localhost", "127.0.0.1", "::1"].includes(u.hostname)
        : false;
      if (u && u.protocol === "http:" && !isLoopback) {
        // eslint-disable-next-line no-console
        console.warn(
          "[scouter] Refusing to send API key over insecure http:// backend " +
            `(${u.host}); use https:// or set the backend on a trusted loopback. ` +
            "API key will not be transmitted.",
        );
        safeApiKey = undefined;
      }
    }

    this.registry = new IntentRegistry();
    this.engine = new ConsequenceEngine(this.mode);
    this.classifier = new ActionTriageClassifier();
    this.interceptor = new ExecutionInterceptor({
      mode: opts.backendUrl ? "hybrid" : this.mode === "audit" ? "audit" : "enforce",
    });

    if (opts.backendUrl) {
      this.backend = new BackendClient(opts.backendUrl, {
        apiKey: safeApiKey,
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
