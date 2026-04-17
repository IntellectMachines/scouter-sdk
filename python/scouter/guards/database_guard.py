"""
DatabaseGuard — Intercepts SQL queries before execution.

Catches: DROP TABLE, SQL injection, bulk deletion, privilege escalation,
data exfiltration via OUTFILE, xp_cmdshell, COPY FROM PROGRAM.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from scouter.guards.base import BaseGuard, GuardDecision, GuardResult

SQL_RULES: List[Dict[str, Any]] = [
    # ── Destructive DDL ───────────────────────────────────────────────────
    {"name": "drop_table",       "pattern": r"\bDROP\s+TABLE\b",         "risk": 95,  "desc": "DROP TABLE — destroys table and data"},
    {"name": "drop_database",    "pattern": r"\bDROP\s+DATABASE\b",      "risk": 100, "desc": "DROP DATABASE — destroys entire database"},
    {"name": "drop_schema",      "pattern": r"\bDROP\s+SCHEMA\b",        "risk": 95,  "desc": "DROP SCHEMA"},
    {"name": "truncate",         "pattern": r"\bTRUNCATE\s+(?:TABLE\s+)?\w", "risk": 90, "desc": "TRUNCATE — removes all rows"},
    {"name": "alter_drop_col",   "pattern": r"\bALTER\s+TABLE\b.*\bDROP\s+COLUMN\b", "risk": 80, "desc": "ALTER TABLE DROP COLUMN"},

    # ── Dangerous DML ─────────────────────────────────────────────────────
    {"name": "delete_no_where",  "pattern": r"\bDELETE\s+FROM\s+\w+\s*(?:;|$)", "risk": 90, "desc": "DELETE without WHERE — deletes all rows"},
    {"name": "update_no_where",  "pattern": r"\bUPDATE\s+\w+\s+SET\b(?!.*\bWHERE\b)", "risk": 85, "desc": "UPDATE without WHERE — modifies all rows"},
    {"name": "delete_always_true","pattern": r"\bDELETE\b.*\bWHERE\b.*(?:1\s*=\s*1|TRUE)", "risk": 90, "desc": "DELETE with always-true WHERE"},

    # ── Privilege escalation ──────────────────────────────────────────────
    {"name": "grant_all",        "pattern": r"\bGRANT\s+ALL\b",           "risk": 80,  "desc": "GRANT ALL PRIVILEGES"},
    {"name": "grant_superuser",  "pattern": r"\bGRANT\b.*\b(?:SUPERUSER|DBA|ADMIN)\b", "risk": 90, "desc": "Granting superuser privileges"},

    # ── SQL injection patterns ────────────────────────────────────────────
    {"name": "union_select",     "pattern": r"\bUNION\s+(?:ALL\s+)?SELECT\b", "risk": 85, "desc": "UNION SELECT — SQL injection"},
    {"name": "stacked_queries",  "pattern": r";\s*(?:DROP|DELETE|INSERT|UPDATE|EXEC|CREATE|ALTER|GRANT)\b", "risk": 85, "desc": "Stacked queries — injection"},
    {"name": "sleep_probe",      "pattern": r"\b(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY|PG_SLEEP)\s*\(", "risk": 70, "desc": "Time-based blind injection"},
    {"name": "load_file",        "pattern": r"\bLOAD_FILE\s*\(|\bINTO\s+(?:OUTFILE|DUMPFILE)\b", "risk": 90, "desc": "File read/write via SQL"},

    # ── System access ─────────────────────────────────────────────────────
    {"name": "xp_cmdshell",      "pattern": r"\b(?:EXEC|EXECUTE)\s+(?:xp_cmdshell|sp_OACreate|sp_configure)\b", "risk": 100, "desc": "SQL Server OS command execution"},
    {"name": "pg_copy_program",  "pattern": r"\bCOPY\s+\w+.*\bFROM\s+PROGRAM\b", "risk": 95, "desc": "PostgreSQL COPY FROM PROGRAM"},
    {"name": "into_outfile",     "pattern": r"\bSELECT\b.*\bINTO\s+OUTFILE\b", "risk": 90, "desc": "Exporting data to server file"},

    # ── Reconnaissance ────────────────────────────────────────────────────
    {"name": "info_schema",      "pattern": r"\bSELECT\b.*\bFROM\s+(?:information_schema|pg_catalog|sys\.)\b", "risk": 50, "desc": "System metadata query"},
    {"name": "select_star_nolim","pattern": r"\bSELECT\s+\*\s+FROM\b(?!.*\bLIMIT\b)(?!.*\bTOP\b)", "risk": 40, "desc": "SELECT * without LIMIT"},
]


class DatabaseGuard(BaseGuard):
    """Intercepts SQL queries before execution."""

    guard_type = "database"

    def __init__(self, mode: str = "enforce", custom_rules: Optional[List[Dict[str, Any]]] = None, read_only: bool = False):
        super().__init__(mode=mode, custom_rules=custom_rules)
        self.read_only = read_only
        self._compiled = []
        for rule in SQL_RULES + (custom_rules or []):
            try:
                self._compiled.append({
                    "name": rule["name"],
                    "risk": rule["risk"],
                    "desc": rule["desc"],
                    "_re": re.compile(rule["pattern"], re.IGNORECASE),
                })
            except re.error:
                pass

    def analyze(self, action: str, context: Dict[str, Any]) -> GuardResult:
        query = action.strip()

        if self.read_only:
            write_pat = re.compile(r"\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE)\b", re.IGNORECASE)
            if write_pat.search(query):
                return GuardResult(
                    decision=GuardDecision.BLOCK, guard_type=self.guard_type, action=action,
                    reason="READ-ONLY mode — write operations blocked", risk_score=80.0,
                    matched_rules=["read_only_violation"],
                )

        matched = []
        max_risk = 0.0
        for rule in self._compiled:
            if rule["_re"].search(query):
                matched.append(rule["name"])
                max_risk = max(max_risk, rule["risk"])

        if max_risk >= 80:
            decision = GuardDecision.BLOCK
        elif max_risk >= 40:
            decision = GuardDecision.WARN
        else:
            decision = GuardDecision.ALLOW

        return GuardResult(
            decision=decision, guard_type=self.guard_type, action=action,
            reason=f"Matched {len(matched)} rule(s): {', '.join(matched)}" if matched else "Query appears safe",
            risk_score=max_risk, matched_rules=matched,
        )
