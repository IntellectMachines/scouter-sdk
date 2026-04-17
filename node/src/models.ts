/**
 * Scouter data models — mirrors sdk/python/scouter/models.py
 */

// ── Enums ─────────────────────────────────────────────────────────────

export enum Decision {
  PASS_THROUGH = "PASS_THROUGH",
  FLAG = "FLAG",
  PAUSE = "PAUSE",
  HARD_STOP = "HARD_STOP",
  ESCALATE = "ESCALATE",
}

export enum ActualExecution {
  AUDIT_PASS = "AUDIT_PASS",
  BLOCKED = "BLOCKED",
}

export enum TriageVerdict {
  SKIP = "SKIP",
  SCAN = "SCAN",
}

export enum GuardDecision {
  ALLOW = "ALLOW",
  BLOCK = "BLOCK",
  WARN = "WARN",
}

// ── Interfaces ────────────────────────────────────────────────────────

export interface Principal {
  user: string;
  role: string;
}

export interface IntentDeclaration {
  intentId: string;
  agentId: string;
  naturalLanguage: string;
  permittedActions: string[];
  excludedActions: string[];
  principalChain: Principal[];
  version: string;
  intentVector?: number[] | null;
}

export interface ActionProposal {
  actionType: string;
  targetSystem: string;
  payloadSummary: string;
  delegationDepth: number;
}

export interface Evaluation {
  irreversibilityScore: number;
  alignmentScore: number;
  calculatedDecision: Decision;
  actualExecution: ActualExecution;
  rationale: string;
}

export interface GovernanceDecision {
  artifactId: string;
  timestamp: string;
  intentId: string;
  action: ActionProposal;
  evaluation: Evaluation;
}

export interface TriageResult {
  verdict: TriageVerdict;
  level: number;
  reason: string;
  category: string;
  matchedTriggers: string[];
  elapsedUs: number;
}

export interface GuardResult {
  decision: GuardDecision;
  guardType: string;
  action: string;
  reason: string;
  riskScore: number;
  matchedRules: string[];
  actionHash: string;
}

export interface LightCheckResult {
  isSuspicious: boolean;
  guardType: string;
  matchedKeywords: string[];
  elapsedUs: number;
  actionPreview: string;
}

// ── API request/response types ────────────────────────────────────────

export interface RegisterIntentParams {
  agentId: string;
  naturalLanguage: string;
  permittedActions: string[];
  excludedActions: string[];
  principalChain?: Array<Record<string, string>>;
  version?: string;
}

export interface ActionPayload {
  actionType: string;
  targetSystem: string;
  payloadSummary: string;
  delegationDepth?: number;
}

export interface MintCredentialParams {
  intentId: string;
  artifactId: string;
  scope?: Record<string, unknown>;
  ttlSeconds?: number;
}
