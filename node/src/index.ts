/**
 * @scouter-ai/core — Runtime Semantic Authorization SDK for AI Agents
 */

// Client
export { ScouterClient, type ScouterClientOptions } from "./client.js";

// Backend HTTP client
export {
  BackendClient,
  type BackendClientOptions,
  type IntentResponse,
  type EvaluationResponse,
  type SpanResponse,
  type AnalyzeTraceResponse,
  type TelemetryStatsResponse,
  type TelemetryRecord,
  type AgentStatsResponse,
  type PromptAnalysisResponse,
  type CredentialResponse,
  type PbacEvalResponse,
  type DIDResponse,
  type DIDKeyRotateResponse,
} from "./api/backend.js";

// Engine
export { IntentRegistry } from "./engine/intent.js";
export { ConsequenceEngine } from "./engine/consequence.js";

// Classifier
export { ActionTriageClassifier, SAFE_TOOLS } from "./classifier/action-triage.js";

// Guards
export { ShellGuard, SHELL_RULES } from "./guards/shell.js";
export { DatabaseGuard, SQL_RULES } from "./guards/database.js";
export { APIGuard, API_RULES } from "./guards/api.js";
export {
  LightGuard,
  SHELL_SUSPICIOUS,
  SQL_SUSPICIOUS,
  API_SUSPICIOUS,
} from "./guards/light.js";
export { ExecutionInterceptor } from "./guards/interceptor.js";
export { BaseGuard, type GuardRule } from "./guards/base.js";

// OpenAI integration
export { wrapOpenAI } from "./integrations/openai.js";

// Models / types
export {
  Decision,
  ActualExecution,
  TriageVerdict,
  GuardDecision,
  type Principal,
  type IntentDeclaration,
  type ActionProposal,
  type Evaluation,
  type GovernanceDecision,
  type TriageResult,
  type GuardResult,
  type LightCheckResult,
  type RegisterIntentParams,
  type ActionPayload,
  type MintCredentialParams,
} from "./models.js";
