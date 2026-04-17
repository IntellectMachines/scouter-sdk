/**
 * Base guard interface and shared types.
 * Mirrors sdk/python/scouter/guards/base.py
 */

import { createHash } from "node:crypto";
import { GuardDecision, type GuardResult } from "../models.js";

export { GuardDecision };
export type { GuardResult };

export interface GuardRule {
  name: string;
  pattern: string;
  risk: number;
  desc: string;
}

export abstract class BaseGuard {
  readonly guardType: string;
  readonly mode: string;
  protected blocked = 0;
  protected warned = 0;
  protected allowed = 0;

  constructor(guardType: string, mode = "enforce") {
    this.guardType = guardType;
    this.mode = mode;
  }

  check(action: string, context: Record<string, unknown> = {}): GuardResult {
    let result = this.analyze(action, context);

    if (result.decision === GuardDecision.BLOCK) this.blocked++;
    else if (result.decision === GuardDecision.WARN) this.warned++;
    else this.allowed++;

    // In audit mode, downgrade BLOCK → WARN
    if (this.mode === "audit" && result.decision === GuardDecision.BLOCK) {
      result = {
        ...result,
        decision: GuardDecision.WARN,
        reason: `[AUDIT] Would block: ${result.reason}`,
      };
    }
    return result;
  }

  protected abstract analyze(
    action: string,
    context: Record<string, unknown>,
  ): GuardResult;

  get stats() {
    return { blocked: this.blocked, warned: this.warned, allowed: this.allowed };
  }

  static hashAction(action: string): string {
    return createHash("sha256").update(action).digest("hex").slice(0, 16);
  }

  protected static buildResult(
    decision: GuardDecision,
    guardType: string,
    action: string,
    reason: string,
    riskScore: number,
    matchedRules: string[],
  ): GuardResult {
    return {
      decision,
      guardType,
      action,
      reason,
      riskScore,
      matchedRules,
      actionHash: BaseGuard.hashAction(action),
    };
  }
}
