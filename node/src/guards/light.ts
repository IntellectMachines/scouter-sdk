/**
 * LightGuard — Ultra-fast client-side suspicion detector.
 * Mirrors sdk/python/scouter/guards/light_guard.py
 *
 * Uses keyword set lookups (NOT regex) for sub-microsecond detection.
 */

import type { LightCheckResult } from "../models.js";

export const SHELL_SUSPICIOUS = new Set<string>([
  "rm -rf", "rm -f", "rmdir", "del /s", "del /f", "format c:",
  "mkfs", "shred", "dd if=", "dd of=",
  "sudo", "su root", "chmod 777", "chown root", "setuid",
  "/dev/tcp", "/dev/udp", "reverse", "revshell", "msfvenom",
  "netcat", " nc -", "ncat ", "bash -i",
  "| bash", "| sh", "| python", "| perl",
  "curl |", "wget |", "wget -o", "downloadstring", "invoke-expression",
  "iex(", "iex ",
  "xmrig", "minerd", "stratum+tcp", "cryptonight",
  "crontab", "authorized_keys", ".ssh/",
  "base64 |", "| curl", "| nc",
  "fork", ":()", "killall", "kill -9", "iptables -f",
  "systemctl stop", "systemctl disable", "ufw disable",
  "reg delete", "format c:", "diskpart", "powershell -c",
  "/etc/shadow", "/etc/passwd", "system32",
]);

export const SQL_SUSPICIOUS = new Set<string>([
  "drop table", "drop database", "drop schema",
  "truncate", "delete from",
  "update ", "alter table",
  "grant all", "grant super", "revoke",
  "union select", "union all select",
  "; drop", "; delete", "; insert", "; update",
  "xp_cmdshell", "sp_oacreate", "sp_configure",
  "copy from program", "into outfile", "into dumpfile",
  "load_file", "information_schema", "pg_catalog",
  "sleep(", "benchmark(", "waitfor delay", "pg_sleep",
  "or 1=1", "or '1'='1", "' or '", "1=1--", "' --",
]);

export const API_SUSPICIOUS = new Set<string>([
  "169.254.169.254", "metadata.google", "metadata.azure",
  "10.", "172.16.", "172.17.", "172.18.", "172.19.",
  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
  "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
  "172.30.", "172.31.",
  "192.168.", "127.0.0.1", "localhost",
  "webhook.site", "requestbin", "hookbin",
  "ngrok.io", "ngrok.app", "trycloudflare",
  "pastebin.com", "ghostbin", "hastebin",
  "../", "..\\",
  "delete /admin", "delete /user", "delete /config",
  "put /config", "put /secret", "put /env",
  "api_key=", "token=", "secret=", "password=",
]);

export class LightGuard {
  private shellKw: Set<string>;
  private sqlKw: Set<string>;
  private apiKw: Set<string>;

  totalChecks = 0;
  fastPassed = 0;
  flagged = 0;

  constructor(opts?: {
    extraShellKeywords?: string[];
    extraSqlKeywords?: string[];
    extraApiKeywords?: string[];
  }) {
    this.shellKw = new Set([...SHELL_SUSPICIOUS, ...(opts?.extraShellKeywords ?? [])]);
    this.sqlKw = new Set([...SQL_SUSPICIOUS, ...(opts?.extraSqlKeywords ?? [])]);
    this.apiKw = new Set([...API_SUSPICIOUS, ...(opts?.extraApiKeywords ?? [])]);
  }

  private check(action: string, keywords: Set<string>, guardType: string): LightCheckResult {
    const t0 = performance.now();
    this.totalChecks++;

    const lower = action.toLowerCase();
    const matched: string[] = [];
    for (const kw of keywords) {
      if (lower.includes(kw)) matched.push(kw);
    }

    const elapsedUs = (performance.now() - t0) * 1000;
    const isSuspicious = matched.length > 0;

    if (isSuspicious) this.flagged++;
    else this.fastPassed++;

    return {
      isSuspicious,
      guardType,
      matchedKeywords: matched,
      elapsedUs,
      actionPreview: action.slice(0, 80),
    };
  }

  checkShell(command: string): LightCheckResult {
    return this.check(command, this.shellKw, "shell");
  }

  checkSql(query: string): LightCheckResult {
    return this.check(query, this.sqlKw, "database");
  }

  checkApi(request: string): LightCheckResult {
    return this.check(request, this.apiKw, "api");
  }

  checkAuto(action: string): LightCheckResult {
    const t0 = performance.now();
    this.totalChecks++;
    const lower = action.toLowerCase();
    const allMatched: string[] = [];
    let guardType = "unknown";

    const shellHits = [...this.shellKw].filter((kw) => lower.includes(kw));
    if (shellHits.length > 0) { allMatched.push(...shellHits); guardType = "shell"; }

    const sqlHits = [...this.sqlKw].filter((kw) => lower.includes(kw));
    if (sqlHits.length > 0) { allMatched.push(...sqlHits); if (!shellHits.length) guardType = "database"; }

    const apiHits = [...this.apiKw].filter((kw) => lower.includes(kw));
    if (apiHits.length > 0) { allMatched.push(...apiHits); if (!shellHits.length && !sqlHits.length) guardType = "api"; }

    const elapsedUs = (performance.now() - t0) * 1000;
    const isSuspicious = allMatched.length > 0;

    if (isSuspicious) this.flagged++;
    else this.fastPassed++;

    return {
      isSuspicious,
      guardType,
      matchedKeywords: allMatched,
      elapsedUs,
      actionPreview: action.slice(0, 80),
    };
  }

  get passRate(): number {
    return this.totalChecks ? (this.fastPassed / this.totalChecks) * 100 : 0;
  }

  get stats() {
    return {
      totalChecks: this.totalChecks,
      fastPassed: this.fastPassed,
      flaggedToServer: this.flagged,
      passRatePct: Math.round(this.passRate * 100) / 100,
    };
  }
}
