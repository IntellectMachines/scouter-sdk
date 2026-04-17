/**
 * IntentRegistry — in-memory, rule-based intent store.
 * Mirrors sdk/python/scouter/engine/intent.py
 */

import { randomUUID } from "node:crypto";
import type { IntentDeclaration, Principal } from "../models.js";

export class IntentRegistry {
  private store = new Map<string, IntentDeclaration>();

  register(opts: {
    agentId: string;
    intent: string;
    permittedActions?: string[];
    excludedActions?: string[];
    permittedDomains?: string[];
    principalChain?: Array<{ user: string; role: string }>;
    version?: string;
  }): IntentDeclaration {
    const actions = [...(opts.permittedActions ?? [])];
    if (opts.permittedDomains) {
      for (const domain of opts.permittedDomains) {
        actions.push(`read:${domain}`, `write:${domain}`);
      }
    }

    const principals: Principal[] = (opts.principalChain ?? []).map((p) => ({
      user: p.user,
      role: p.role,
    }));

    const declaration: IntentDeclaration = {
      intentId: randomUUID(),
      agentId: opts.agentId,
      naturalLanguage: opts.intent,
      permittedActions: actions,
      excludedActions: opts.excludedActions ?? [],
      principalChain: principals,
      version: opts.version ?? "1.0",
      intentVector: null,
    };

    this.store.set(declaration.intentId, declaration);
    return declaration;
  }

  get(intentId: string): IntentDeclaration | undefined {
    return this.store.get(intentId);
  }

  getByAgent(agentId: string): IntentDeclaration | undefined {
    for (const decl of this.store.values()) {
      if (decl.agentId === agentId) return decl;
    }
    return undefined;
  }
}
