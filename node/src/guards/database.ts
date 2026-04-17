/**
 * DatabaseGuard — Intercepts SQL queries before execution.
 * Mirrors sdk/python/scouter/guards/database_guard.py (17+ regex rules).
 */

import { GuardDecision } from "../models.js";
import { BaseGuard, type GuardRule, type GuardResult } from "./base.js";

export const SQL_RULES: GuardRule[] = [
  // Destructive DDL
  { name: "drop_table",       pattern: "\\bDROP\\s+TABLE\\b",                             risk: 95,  desc: "DROP TABLE — destroys table and data" },
  { name: "drop_database",    pattern: "\\bDROP\\s+DATABASE\\b",                          risk: 100, desc: "DROP DATABASE — destroys entire database" },
  { name: "drop_schema",      pattern: "\\bDROP\\s+SCHEMA\\b",                            risk: 95,  desc: "DROP SCHEMA" },
  { name: "truncate",         pattern: "\\bTRUNCATE\\s+(?:TABLE\\s+)?\\w",                risk: 90,  desc: "TRUNCATE — removes all rows" },
  { name: "alter_drop_col",   pattern: "\\bALTER\\s+TABLE\\b.*\\bDROP\\s+COLUMN\\b",     risk: 80,  desc: "ALTER TABLE DROP COLUMN" },
  // Dangerous DML
  { name: "delete_no_where",  pattern: "\\bDELETE\\s+FROM\\s+\\w+\\s*(?:;|$)",           risk: 90,  desc: "DELETE without WHERE — deletes all rows" },
  { name: "update_no_where",  pattern: "\\bUPDATE\\s+\\w+\\s+SET\\b(?!.*\\bWHERE\\b)",   risk: 85,  desc: "UPDATE without WHERE — modifies all rows" },
  { name: "delete_always_true", pattern: "\\bDELETE\\b.*\\bWHERE\\b.*(?:1\\s*=\\s*1|TRUE)", risk: 90, desc: "DELETE with always-true WHERE" },
  // Privilege escalation
  { name: "grant_all",        pattern: "\\bGRANT\\s+ALL\\b",                              risk: 80,  desc: "GRANT ALL PRIVILEGES" },
  { name: "grant_superuser",  pattern: "\\bGRANT\\b.*\\b(?:SUPERUSER|DBA|ADMIN)\\b",     risk: 90,  desc: "Granting superuser privileges" },
  // SQL injection
  { name: "union_select",     pattern: "\\bUNION\\s+(?:ALL\\s+)?SELECT\\b",              risk: 85,  desc: "UNION SELECT — SQL injection" },
  { name: "stacked_queries",  pattern: ";\\s*(?:DROP|DELETE|INSERT|UPDATE|EXEC|CREATE|ALTER|GRANT)\\b", risk: 85, desc: "Stacked queries — injection" },
  { name: "sleep_probe",      pattern: "\\b(?:SLEEP|BENCHMARK|WAITFOR\\s+DELAY|PG_SLEEP)\\s*\\(", risk: 70, desc: "Time-based blind injection" },
  { name: "load_file",        pattern: "\\bLOAD_FILE\\s*\\(|\\bINTO\\s+(?:OUTFILE|DUMPFILE)\\b", risk: 90, desc: "File read/write via SQL" },
  // System access
  { name: "xp_cmdshell",      pattern: "\\b(?:EXEC|EXECUTE)\\s+(?:xp_cmdshell|sp_OACreate|sp_configure)\\b", risk: 100, desc: "SQL Server OS command execution" },
  { name: "pg_copy_program",  pattern: "\\bCOPY\\s+\\w+.*\\bFROM\\s+PROGRAM\\b",         risk: 95,  desc: "PostgreSQL COPY FROM PROGRAM" },
  { name: "into_outfile",     pattern: "\\bSELECT\\b.*\\bINTO\\s+OUTFILE\\b",             risk: 90,  desc: "Exporting data to server file" },
  // Reconnaissance
  { name: "info_schema",      pattern: "\\bSELECT\\b.*\\bFROM\\s+(?:information_schema|pg_catalog|sys\\.)\\b", risk: 50, desc: "System metadata query" },
  { name: "select_star_nolim", pattern: "\\bSELECT\\s+\\*\\s+FROM\\b(?!.*\\bLIMIT\\b)(?!.*\\bTOP\\b)", risk: 40, desc: "SELECT * without LIMIT" },
];

export class DatabaseGuard extends BaseGuard {
  private compiled: Array<{ name: string; risk: number; desc: string; re: RegExp }>;
  private readOnly: boolean;

  constructor(mode = "enforce", opts?: { customRules?: GuardRule[]; readOnly?: boolean }) {
    super("database", mode);
    this.readOnly = opts?.readOnly ?? false;
    this.compiled = [];
    for (const rule of [...SQL_RULES, ...(opts?.customRules ?? [])]) {
      try {
        this.compiled.push({ name: rule.name, risk: rule.risk, desc: rule.desc, re: new RegExp(rule.pattern, "i") });
      } catch { /* skip invalid regex */ }
    }
  }

  protected analyze(action: string, _context: Record<string, unknown>): GuardResult {
    const query = action.trim();

    if (this.readOnly) {
      const writePat = /\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE)\b/i;
      if (writePat.test(query)) {
        return BaseGuard.buildResult(
          GuardDecision.BLOCK, this.guardType, action,
          "READ-ONLY mode — write operations blocked", 80, ["read_only_violation"],
        );
      }
    }

    const matched: string[] = [];
    let maxRisk = 0;

    for (const rule of this.compiled) {
      if (rule.re.test(query)) {
        matched.push(rule.name);
        maxRisk = Math.max(maxRisk, rule.risk);
      }
    }

    const decision = maxRisk >= 80 ? GuardDecision.BLOCK : maxRisk >= 40 ? GuardDecision.WARN : GuardDecision.ALLOW;

    return BaseGuard.buildResult(
      decision, this.guardType, action,
      matched.length > 0 ? `Matched ${matched.length} rule(s): ${matched.join(", ")}` : "Query appears safe",
      maxRisk, matched,
    );
  }
}
