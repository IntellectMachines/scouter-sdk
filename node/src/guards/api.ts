/**
 * APIGuard — Intercepts outbound HTTP/API requests before execution.
 * Mirrors sdk/python/scouter/guards/api_guard.py (9+ regex rules).
 */

import { GuardDecision } from "../models.js";
import { BaseGuard, type GuardRule, type GuardResult } from "./base.js";

export const API_RULES: GuardRule[] = [
  { name: "aws_metadata",     pattern: "169\\.254\\.169\\.254|metadata\\.google\\.internal|metadata\\.azure\\.com", risk: 95, desc: "Cloud metadata SSRF" },
  { name: "internal_net",     pattern: "(?:^|\\/|@)(?:10\\.\\d+\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+|127\\.0\\.0\\.1|localhost)", risk: 70, desc: "Internal/private network" },
  { name: "delete_admin",     pattern: "DELETE.*(?:/admin|/users|/accounts|/database|/system|/config)", risk: 90, desc: "DELETE on admin endpoint" },
  { name: "put_secrets",      pattern: "PUT.*(?:/config|/settings|/environment|/\\.env|/secrets)", risk: 80, desc: "PUT modifying config/secrets" },
  { name: "webhook_exfil",    pattern: "(?:webhook\\.site|requestbin\\.com|hookbin\\.com|pipedream\\.net|burpcollaborator)", risk: 85, desc: "Known exfiltration service" },
  { name: "ngrok_tunnel",     pattern: "\\.ngrok\\.io|\\.ngrok\\.app|\\.trycloudflare\\.com", risk: 75, desc: "Tunnel service — exfiltration risk" },
  { name: "pastebin_upload",  pattern: "(?:pastebin\\.com|hastebin\\.com|paste\\.ee|ghostbin)", risk: 80, desc: "Paste service upload" },
  { name: "path_traversal",   pattern: "(?:\\.\\./|\\.\\.\\\\/|%2e%2e%2f|%2e%2e\\/){2,}", risk: 90, desc: "Path traversal in URL" },
  { name: "cred_in_url",      pattern: "(?:api_key|token|secret|password|auth)\\s*[=:]\\s*['\"]?\\w{8,}", risk: 85, desc: "Credentials in request" },
];

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);

export class APIGuard extends BaseGuard {
  private compiled: Array<{ name: string; risk: number; desc: string; re: RegExp }>;
  private allowedDomains: string[];
  private blockedDomains: string[];

  constructor(
    mode = "enforce",
    opts?: {
      customRules?: GuardRule[];
      allowedDomains?: string[];
      blockedDomains?: string[];
    },
  ) {
    super("api", mode);
    this.allowedDomains = (opts?.allowedDomains ?? []).map((d) => d.toLowerCase());
    this.blockedDomains = (opts?.blockedDomains ?? []).map((d) => d.toLowerCase());
    this.compiled = [];
    for (const rule of [...API_RULES, ...(opts?.customRules ?? [])]) {
      try {
        this.compiled.push({ name: rule.name, risk: rule.risk, desc: rule.desc, re: new RegExp(rule.pattern, "i") });
      } catch { /* skip invalid regex */ }
    }
  }

  protected analyze(action: string, context: Record<string, unknown>): GuardResult {
    const parts = action.trim().split(/\s+/);
    let method: string;
    let url: string;

    if (parts.length >= 2 && HTTP_METHODS.has(parts[0].toUpperCase())) {
      method = parts[0].toUpperCase();
      url = parts.slice(1).join(" ");
    } else {
      method = ((context.method as string) ?? "GET").toUpperCase();
      url = action.trim();
    }

    let domain = "";
    try {
      const fullUrl = url.includes("://") ? url : `https://${url}`;
      domain = new URL(fullUrl).hostname.toLowerCase();
    } catch { /* ignore parse errors */ }

    // Domain whitelist
    if (this.allowedDomains.length > 0 && domain) {
      const allowed = this.allowedDomains.some(
        (d) => domain === d || domain.endsWith(`.${d}`),
      );
      if (!allowed) {
        return BaseGuard.buildResult(
          GuardDecision.BLOCK, this.guardType, action,
          `Domain '${domain}' not in allowed list`, 75, ["domain_not_allowed"],
        );
      }
    }

    // Domain blocklist
    if (domain && this.blockedDomains.some((d) => domain === d || domain.endsWith(`.${d}`))) {
      return BaseGuard.buildResult(
        GuardDecision.BLOCK, this.guardType, action,
        `Domain '${domain}' is blocked`, 90, ["domain_blocked"],
      );
    }

    const fullAction = `${method} ${url}`;
    const matched: string[] = [];
    let maxRisk = 0;

    for (const rule of this.compiled) {
      if (rule.re.test(fullAction)) {
        matched.push(rule.name);
        maxRisk = Math.max(maxRisk, rule.risk);
      }
    }

    const decision = maxRisk >= 80 ? GuardDecision.BLOCK : maxRisk >= 40 ? GuardDecision.WARN : GuardDecision.ALLOW;

    return BaseGuard.buildResult(
      decision, this.guardType, action,
      matched.length > 0 ? `Matched ${matched.length} rule(s): ${matched.join(", ")}` : "Request appears safe",
      maxRisk, matched,
    );
  }
}
