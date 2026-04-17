/**
 * ConsequenceEngine — Score-based, audit mode (Phase 1).
 * Mirrors sdk/python/scouter/engine/consequence.py
 */

import { randomUUID } from "node:crypto";
import {
  Decision,
  ActualExecution,
  type ActionProposal,
  type Evaluation,
  type GovernanceDecision,
  type IntentDeclaration,
} from "../models.js";

// STD §3.2 — static irreversibility map
const IRREVERSIBILITY: Record<string, number> = {
  read: 0.05,
  list: 0.05,
  search: 0.05,
  get: 0.05,
  write: 0.35,
  create: 0.40,
  update: 0.45,
  send: 0.70,
  "send:external": 0.75,
  execute: 0.65,
  delete: 0.95,
  drop: 0.95,
};

// Pre-sorted longest-first for correct prefix matching
const SORTED_IRREV = Object.entries(IRREVERSIBILITY).sort(
  (a, b) => b[0].length - a[0].length,
);

function irreversibilityScore(actionType: string): number {
  const lower = actionType.toLowerCase();
  for (const [key, score] of SORTED_IRREV) {
    if (lower.startsWith(key) || lower.includes(key)) return score;
  }
  return 0.50;
}

function keywordAlignment(
  action: ActionProposal,
  intent: IntentDeclaration,
): number {
  const actionText =
    `${action.actionType} ${action.targetSystem} ${action.payloadSummary}`.toLowerCase();
  const actionParts = new Set(
    actionText.replace(/[:_]/g, " ").split(/\s+/),
  );

  for (const perm of intent.permittedActions) {
    const permLower = perm.toLowerCase();
    const permParts = new Set(permLower.replace(/[:_]/g, " ").split(/\s+/));
    if (actionText.includes(permLower) || isSubset(permParts, actionParts)) {
      return 0.90;
    }
  }

  for (const excl of intent.excludedActions) {
    const exclLower = excl.toLowerCase();
    const exclParts = new Set(exclLower.replace(/[:_]/g, " ").split(/\s+/));
    if (actionText.includes(exclLower) || isSubset(exclParts, actionParts)) {
      return 0.10;
    }
  }

  const intentTokens = new Set(intent.naturalLanguage.toLowerCase().split(/\s+/));
  const actionTokens = new Set(actionText.split(/\s+/));
  if (intentTokens.size === 0) return 0.50;
  let overlap = 0;
  for (const t of intentTokens) {
    if (actionTokens.has(t)) overlap++;
  }
  return Math.round(Math.min(overlap / intentTokens.size + 0.30, 1.0) * 100) / 100;
}

function isSubset(sub: Set<string>, sup: Set<string>): boolean {
  for (const v of sub) {
    if (!sup.has(v)) return false;
  }
  return true;
}

function decide(irreversibility: number, alignment: number): Decision {
  if (irreversibility > 0.8) return Decision.ESCALATE;
  if (irreversibility > 0.6 && alignment < 0.6) return Decision.HARD_STOP;
  if (irreversibility < 0.3 && alignment > 0.7) return Decision.PASS_THROUGH;
  if (alignment < 0.5) return Decision.FLAG;
  return Decision.PASS_THROUGH;
}

export class ConsequenceEngine {
  readonly mode: string;

  constructor(mode = "audit") {
    this.mode = mode;
  }

  evaluate(
    action: ActionProposal,
    intent?: IntentDeclaration,
  ): GovernanceDecision {
    const irrev = irreversibilityScore(action.actionType);
    const alignment = intent ? keywordAlignment(action, intent) : 0.50;

    const penalty = Math.min(0.4, action.delegationDepth * 0.08);
    const finalScore = alignment * (1.0 - penalty);

    const calculated = decide(irrev, finalScore);

    const rationaleParts: string[] = [];
    if (irrev > 0.6) rationaleParts.push("High irreversibility");
    if (finalScore < 0.6) rationaleParts.push("Low intent alignment");
    if (rationaleParts.length === 0)
      rationaleParts.push("Action within expected parameters");

    const evaluation: Evaluation = {
      irreversibilityScore: Math.round(irrev * 100) / 100,
      alignmentScore: Math.round(finalScore * 100) / 100,
      calculatedDecision: calculated,
      actualExecution: ActualExecution.AUDIT_PASS,
      rationale: rationaleParts.join("; ") + ".",
    };

    return {
      artifactId: randomUUID(),
      timestamp: new Date().toISOString(),
      intentId: intent?.intentId ?? "",
      action,
      evaluation,
    };
  }
}
