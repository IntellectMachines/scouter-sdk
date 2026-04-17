/**
 * ExecutionInterceptor — Central orchestrator for all execution guards.
 * Mirrors sdk/python/scouter/guards/execution_interceptor.py
 *
 * Modes:
 *   enforce — Full local guards (all 60+ regex rules)
 *   audit   — Like enforce but BLOCK → WARN
 *   hybrid  — LightGuard locally, suspicious → server fallback to local
 */

import { GuardDecision, type GuardResult } from "../models.js";
import { ShellGuard } from "./shell.js";
import { DatabaseGuard } from "./database.js";
import { APIGuard } from "./api.js";
import { LightGuard } from "./light.js";
import { BaseGuard } from "./base.js";

export class ExecutionInterceptor {
  readonly mode: string;
  readonly shellGuard: ShellGuard;
  readonly databaseGuard: DatabaseGuard;
  readonly apiGuard: APIGuard;
  private lightGuard: LightGuard | null = null;
  private auditLog: GuardResult[] = [];

  constructor(opts?: {
    mode?: string;
    allowedDomains?: string[];
    blockedDomains?: string[];
    dbReadOnly?: boolean;
  }) {
    this.mode = opts?.mode ?? "enforce";

    const guardMode = this.mode === "hybrid" ? "enforce" : this.mode;
    this.shellGuard = new ShellGuard(guardMode);
    this.databaseGuard = new DatabaseGuard(guardMode, { readOnly: opts?.dbReadOnly });
    this.apiGuard = new APIGuard(guardMode, {
      allowedDomains: opts?.allowedDomains,
      blockedDomains: opts?.blockedDomains,
    });

    if (this.mode === "hybrid") {
      this.lightGuard = new LightGuard();
    }
  }

  checkShell(command: string, context?: Record<string, unknown>): GuardResult {
    if (this.mode === "hybrid") return this.hybridCheck("shell", command, context);
    const result = this.shellGuard.check(command, context);
    this.auditLog.push(result);
    return result;
  }

  checkDatabase(query: string, context?: Record<string, unknown>): GuardResult {
    if (this.mode === "hybrid") return this.hybridCheck("database", query, context);
    const result = this.databaseGuard.check(query, context);
    this.auditLog.push(result);
    return result;
  }

  checkApi(request: string, context?: Record<string, unknown>): GuardResult {
    if (this.mode === "hybrid") return this.hybridCheck("api", request, context);
    const result = this.apiGuard.check(request, context);
    this.auditLog.push(result);
    return result;
  }

  private hybridCheck(
    guardType: string,
    action: string,
    context?: Record<string, unknown>,
  ): GuardResult {
    const lg = this.lightGuard!;

    // Step 1: LightGuard check
    const lightResult =
      guardType === "shell" ? lg.checkShell(action) :
      guardType === "database" ? lg.checkSql(action) :
      lg.checkApi(action);

    // Step 2: Fast pass (99% of actions)
    if (!lightResult.isSuspicious) {
      const result: GuardResult = {
        decision: GuardDecision.ALLOW,
        guardType,
        action,
        reason: "No suspicious keywords — passed locally",
        riskScore: 0,
        matchedRules: [],
        actionHash: BaseGuard.hashAction(action),
      };
      this.auditLog.push(result);
      return result;
    }

    // Step 3: Fallback to full local guards
    const localGuard =
      guardType === "shell" ? this.shellGuard :
      guardType === "database" ? this.databaseGuard :
      this.apiGuard;

    const result = localGuard.check(action, context);
    this.auditLog.push(result);
    return result;
  }

  get log(): Array<Record<string, unknown>> {
    return this.auditLog.map((r) => ({
      guardType: r.guardType,
      decision: r.decision,
      actionHash: r.actionHash,
      riskScore: r.riskScore,
      reason: r.reason,
      matchedRules: r.matchedRules,
    }));
  }

  get stats() {
    const base: Record<string, unknown> = {
      shell: this.shellGuard.stats,
      database: this.databaseGuard.stats,
      api: this.apiGuard.stats,
    };
    if (this.lightGuard) {
      base.lightGuard = this.lightGuard.stats;
    }
    return base;
  }
}
