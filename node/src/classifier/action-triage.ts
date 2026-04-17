/**
 * ActionTriageClassifier — Multi-level short-circuit classifier.
 * Mirrors sdk/python/scouter/classifier/action_triage.py
 *
 * Levels:
 *   0: Tool name lookup (O(1) Set)
 *   1: Dangerous tool prefix (O(k))
 *   2: Argument keyword scan (O(n))
 *   3: Structural pattern detect (regex)
 *   4: Text completion triage
 */

import { TriageVerdict, type TriageResult } from "../models.js";

// ═══════════════════════════════════════════════════════════════════════
// CLASSIFICATION DATA
// ═══════════════════════════════════════════════════════════════════════

export const SAFE_TOOLS = new Set<string>([
  "search_knowledge_base", "search_docs", "search_faq", "search",
  "query_knowledge", "lookup_info", "get_info", "get_help",
  "lookup_order", "get_order", "get_order_status", "check_status",
  "get_product", "list_products", "search_products",
  "get_user_info", "get_profile", "get_account",
  "check_refund_eligibility", "check_eligibility",
  "get_weather", "get_time", "calculate", "convert_currency",
  "read_file", "list_files", "search_code", "get_file_content",
  "analyze_code", "lint_code", "format_code",
]);

const DANGEROUS_TOOL_PREFIXES: string[] = [
  "exec", "run_", "shell", "bash", "cmd", "command", "subprocess",
  "system", "spawn", "terminal", "powershell",
  "create_file", "write_file", "delete_file", "remove_file",
  "move_file", "rename_file", "upload_file", "download_file",
  "insert", "update_", "delete_", "drop_", "create_table",
  "alter_", "truncate", "migrate",
  "send_email", "send_message", "send_sms", "post_", "put_",
  "http_post", "http_put", "http_delete", "webhook",
  "call_api", "invoke_api",
  "process_refund", "refund", "charge", "payment", "transfer",
  "payout", "withdraw", "invoice",
  "deploy", "provision", "terminate", "destroy", "scale",
  "create_instance", "delete_instance", "create_bucket",
  "delete_bucket", "create_database", "delete_database",
  "revoke", "grant", "change_password", "reset_password",
  "create_user", "delete_user", "modify_permissions",
];

const ARGUMENT_TRIGGERS = new Set<string>([
  "rm -rf", "rm -f", "sudo", "chmod", "chown", "kill",
  "/bin/", "/usr/bin/", "/etc/", "/dev/", "system32",
  "subprocess", "os.system", "exec(", "eval(",
  "bash -c", "sh -c", "cmd /c", "powershell",
  "drop table", "drop database", "truncate", "delete from",
  "insert into", "update set", "alter table", "grant all",
  "union select", "xp_cmdshell",
  "/etc/passwd", "/etc/shadow", "~/.ssh",
  "authorized_keys", ".env", "credentials",
  "../", "..\\",
  "api.stripe.com", "stripe.com", "stripe",
  "supabase.co", "supabase",
  "pinecone.io", "pinecone",
  "api.github.com", "github",
  "api.twilio.com", "twilio",
  "api.sendgrid.com", "sendgrid",
  "firestore.googleapis.com", "firebase",
  "s3.amazonaws.com", "ec2.amazonaws", "rds.amazonaws",
  "lambda.amazonaws", "iam.amazonaws",
  "googleapis.com",
  "refund", "payout", "transfer", "withdraw",
  "charge", "payment_intent", "subscription",
  "credit_card", "bank_account",
  "169.254.169.254", "metadata.google", "metadata.azure",
  "webhook.site", "requestbin", "ngrok",
  "pastebin.com", "ghostbin",
  "curl ", "wget ", "fetch(",
]);

interface StructuralPattern {
  name: string;
  regex: RegExp;
  category: string;
}

const STRUCTURAL_PATTERNS: StructuralPattern[] = [
  { name: "file_path_unix",  regex: /\/(?:etc|var|tmp|home|root|usr|bin|opt|dev)\//i,           category: "filesystem" },
  { name: "file_path_win",   regex: /[A-Z]:\\(?:Windows|Users|Program|System)/i,                category: "filesystem" },
  { name: "shell_pipe",      regex: /\|(?:\s*(?:bash|sh|python|perl|ruby|exec))/i,              category: "system" },
  { name: "shell_redirect",  regex: /(?:>>?|2>&1)\s*\//i,                                       category: "system" },
  { name: "shell_semicolon", regex: /;\s*(?:rm|drop|delete|kill|curl|wget|sudo|chmod)/i,         category: "system" },
  { name: "shell_backtick",  regex: /`[^`]*(?:rm|curl|wget|exec|eval|sudo)/i,                   category: "system" },
  { name: "sql_ddl",         regex: /\b(?:DROP|CREATE|ALTER|TRUNCATE)\s+(?:TABLE|DATABASE|INDEX|SCHEMA)\b/i, category: "database" },
  { name: "sql_dangerous",   regex: /\b(?:DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b/i,                category: "database" },
  { name: "url_with_action", regex: /https?:\/\/[^\s]+\/(?:delete|destroy|terminate|refund|transfer|payout)/i, category: "api" },
  { name: "cloud_api",       regex: /(?:amazonaws\.com|googleapis\.com|azure\.com|supabase\.co|pinecone\.io)/i, category: "cloud" },
  { name: "ip_internal",     regex: /(?:127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.)/i, category: "api" },
];

const PROMPT_ACTION_PATTERNS: StructuralPattern[] = [
  { name: "destroy_system",    regex: /\b(?:delete|remove|destroy|wipe|nuke|erase|obliterate)\b.*\b(?:all|every|entire|database|table|server|system|files?|codebase|repo(?:sitory)?|bucket|cluster|index)\b/i, category: "system" },
  { name: "shell_exec",        regex: /\b(?:run|execute|exec|launch|invoke|spawn)\b.*\b(?:command|script|shell|bash|terminal|cmd|powershell|subprocess)\b/i, category: "system" },
  { name: "shell_inline",      regex: /\b(?:rm\s+-rf|sudo\s|chmod\s|kill\s+-9|dd\s+if=|mkfs\s|format\s+[A-Z]:)/i, category: "system" },
  { name: "db_destructive",    regex: /\b(?:drop|truncate)\b.*\b(?:table|database|schema|collection|index)\b/i, category: "database" },
  { name: "db_bulk_mutation",   regex: /\b(?:delete\s+from|update\s+\w+\s+set)\b.*\b(?:where\s+1\s*=\s*1|all|every|without\s+(?:condition|where|filter))\b/i, category: "database" },
  { name: "financial_action",  regex: /\b(?:refund|charge|transfer|payout|withdraw|send\s+money|wire\s+transfer)\b.*\b(?:\$[\d,.]+|amount|money|payment|funds?|account|balance|invoice)\b/i, category: "financial" },
  { name: "large_refund",      regex: /\b(?:refund|reimburse|credit\s+back)\b.*\$\s*[\d,]*[5-9]\d{2,}|\$\s*[\d,]*\d{4,}/i, category: "financial" },
  { name: "third_party_action", regex: /\b(?:call|invoke|send|post|delete|connect|use)\b.*\b(?:stripe|supabase|pinecone|aws|firebase|twilio|sendgrid|github|vercel|cloudflare|openai|anthropic)\b/i, category: "third_party_api" },
  { name: "cloud_lifecycle",   regex: /\b(?:terminate|destroy|delete|remove|deprovision|shutdown|scale\s+down)\b.*\b(?:instance|server|bucket|cluster|function|resource|vm|container|pod|node|lambda)\b/i, category: "cloud" },
  { name: "fs_mutation",       regex: /\b(?:create|write|modify|overwrite|delete|remove)\b.*\b(?:file|directory|folder|config|\.env|credentials|\.ssh|authorized_keys)\b/i, category: "filesystem" },
  { name: "prompt_injection",  regex: /\b(?:ignore|forget|disregard|override|bypass|skip)\b.*\b(?:instructions?|rules?|guidelines?|previous|system\s+prompt|security|restrictions?|safety)\b/i, category: "injection" },
  { name: "data_exfiltration", regex: /\b(?:send|email|upload|post|transfer|exfiltrate|steal|dump|extract)\b.*\b(?:data|records?|information|credentials?|passwords?|keys?|tokens?|secrets?|PII|customer|user)\b/i, category: "api" },
  { name: "credential_access", regex: /\b(?:give|grant|show|reveal|expose|display)\b.*\b(?:admin|root|superuser|password|secret|key|token|credential|access|permission)\b/i, category: "system" },
];

// ═══════════════════════════════════════════════════════════════════════
// CLASSIFIER
// ═══════════════════════════════════════════════════════════════════════

export class ActionTriageClassifier {
  private safeTools: Set<string>;
  private dangerousPrefixes: string[];
  private argumentTriggers: Set<string>;
  private toolNameCache = new Map<string, [TriageVerdict, string, string]>();

  totalClassified = 0;
  skipped = 0;
  scanned = 0;

  constructor(opts?: {
    extraSafeTools?: string[];
    extraDangerousPrefixes?: string[];
    extraTriggers?: string[];
  }) {
    this.safeTools = new Set([...SAFE_TOOLS, ...(opts?.extraSafeTools ?? [])]);
    this.dangerousPrefixes = [...DANGEROUS_TOOL_PREFIXES, ...(opts?.extraDangerousPrefixes ?? [])];
    this.argumentTriggers = new Set([...ARGUMENT_TRIGGERS, ...(opts?.extraTriggers ?? [])]);
  }

  classifyToolCall(toolName: string, args = ""): TriageResult {
    const t0 = performance.now();
    this.totalClassified++;
    const toolLower = toolName.toLowerCase();
    const argsLower = args.toLowerCase();

    // Level 0: Known-safe tool
    if (this.safeTools.has(toolLower)) {
      if (!argsLower || !this.hasArgumentTriggers(argsLower)) {
        return this.result(TriageVerdict.SKIP, 0, "Known safe tool", "safe_tool", [], t0);
      }
    }

    // Level 0 cache
    if (this.toolNameCache.has(toolLower) && !argsLower) {
      const [v, r, c] = this.toolNameCache.get(toolLower)!;
      return this.result(v, 0, `Cached: ${r}`, c, [], t0);
    }

    // Level 1: Dangerous prefix
    for (const prefix of this.dangerousPrefixes) {
      if (toolLower.startsWith(prefix) || toolLower === prefix) {
        this.toolNameCache.set(toolLower, [TriageVerdict.SCAN, `Dangerous tool: ${prefix}`, "dangerous_tool"]);
        return this.result(TriageVerdict.SCAN, 1, `Dangerous tool prefix: ${prefix}`, "dangerous_tool", [prefix], t0);
      }
    }

    // Level 2: Argument keyword scan
    if (argsLower) {
      const triggers = this.findArgumentTriggers(argsLower);
      if (triggers.length > 0) {
        const category = this.categorizeTriggers(triggers);
        return this.result(TriageVerdict.SCAN, 2, `Argument triggers: ${triggers.slice(0, 3).join(", ")}`, category, triggers, t0);
      }
    }

    // Level 3: Structural patterns
    if (argsLower) {
      for (const { name, regex, category } of STRUCTURAL_PATTERNS) {
        if (regex.test(argsLower)) {
          return this.result(TriageVerdict.SCAN, 3, `Structural pattern: ${name}`, category, [name], t0);
        }
      }
    }

    // Default: unknown tool
    if (!this.safeTools.has(toolLower) && !this.toolNameCache.has(toolLower)) {
      this.toolNameCache.set(toolLower, [TriageVerdict.SKIP, "No danger signals on first encounter", "unknown_tool"]);
      return this.result(TriageVerdict.SKIP, 0, "Unknown tool, no danger signals", "unknown_tool", [], t0);
    }

    return this.result(TriageVerdict.SKIP, 0, "No danger signals detected", "safe_tool", [], t0);
  }

  classifyCompletion(content: string): TriageResult {
    const t0 = performance.now();
    this.totalClassified++;

    if (!content || content.length < 10) {
      return this.result(TriageVerdict.SKIP, 4, "Empty or trivial content", "conversation", [], t0);
    }

    const lower = content.toLowerCase();

    for (const { name, regex, category } of STRUCTURAL_PATTERNS) {
      if (regex.test(lower)) {
        return this.result(TriageVerdict.SCAN, 3, `Structural pattern in completion: ${name}`, category, [name], t0);
      }
    }

    const triggers = this.findArgumentTriggers(lower);
    if (triggers.length > 0) {
      const category = this.categorizeTriggers(triggers);
      return this.result(TriageVerdict.SCAN, 2, `Keyword triggers in completion: ${triggers.slice(0, 3).join(", ")}`, category, triggers, t0);
    }

    return this.result(TriageVerdict.SKIP, 4, "Pure conversational content", "conversation", [], t0);
  }

  classifyPrompt(prompt: string): TriageResult {
    const t0 = performance.now();
    this.totalClassified++;

    if (!prompt || prompt.length < 5) {
      return this.result(TriageVerdict.SKIP, 0, "Empty or trivial prompt", "conversation", [], t0);
    }

    const lower = prompt.toLowerCase();

    // Level 1: Prompt action patterns
    for (const { name, regex, category } of PROMPT_ACTION_PATTERNS) {
      if (regex.test(lower)) {
        return this.result(TriageVerdict.SCAN, 1, `Prompt action pattern: ${name}`, category, [name], t0);
      }
    }

    // Level 2: Keyword triggers
    const triggers = this.findArgumentTriggers(lower);
    if (triggers.length > 0) {
      const category = this.categorizeTriggers(triggers);
      return this.result(TriageVerdict.SCAN, 2, `Keyword triggers in prompt: ${triggers.slice(0, 3).join(", ")}`, category, triggers, t0);
    }

    // Level 3: Structural patterns
    for (const { name, regex, category } of STRUCTURAL_PATTERNS) {
      if (regex.test(lower)) {
        return this.result(TriageVerdict.SCAN, 3, `Structural pattern in prompt: ${name}`, category, [name], t0);
      }
    }

    return this.result(TriageVerdict.SKIP, 4, "Conversational prompt — no actionable signals", "conversation", [], t0);
  }

  get stats() {
    return {
      totalClassified: this.totalClassified,
      skipped: this.skipped,
      scanned: this.scanned,
      skipRatePct: this.totalClassified
        ? Math.round((this.skipped / this.totalClassified) * 10000) / 100
        : 0,
      cacheSize: this.toolNameCache.size,
    };
  }

  // ── Private helpers ─────────────────────────────────────────────

  private hasArgumentTriggers(text: string): boolean {
    for (const trigger of this.argumentTriggers) {
      if (text.includes(trigger)) return true;
    }
    return false;
  }

  private findArgumentTriggers(text: string): string[] {
    const found: string[] = [];
    for (const trigger of this.argumentTriggers) {
      if (text.includes(trigger)) found.push(trigger);
    }
    return found;
  }

  private categorizeTriggers(triggers: string[]): string {
    for (const t of triggers) {
      if (["stripe", "twilio", "sendgrid", "supabase", "pinecone", "firebase", "github"].some((s) => t.includes(s))) return "third_party_api";
      if (["amazonaws", "googleapis", "azure"].some((s) => t.includes(s))) return "cloud";
      if (["drop ", "delete from", "truncate", "insert", "update", "xp_cmd"].some((s) => t.includes(s))) return "database";
      if (["/etc/", "/dev/", "sudo", "chmod", "rm -", "bash", "shell", "subprocess"].some((s) => t.includes(s))) return "system";
      if ([".env", "credentials", "authorized_keys", "../"].some((s) => t.includes(s))) return "filesystem";
      if (["refund", "payout", "transfer", "charge", "payment", "withdraw"].some((s) => t.includes(s))) return "financial";
    }
    return "api";
  }

  private result(
    verdict: TriageVerdict,
    level: number,
    reason: string,
    category: string,
    triggers: string[],
    t0: number,
  ): TriageResult {
    const elapsedUs = (performance.now() - t0) * 1000;
    if (verdict === TriageVerdict.SKIP) this.skipped++;
    else this.scanned++;
    return { verdict, level, reason, category, matchedTriggers: triggers, elapsedUs };
  }
}
