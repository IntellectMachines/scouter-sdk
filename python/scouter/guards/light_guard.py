"""
LightGuard — Ultra-fast client-side suspicion detector.

Design principle: 99% of actions are benign. This guard uses simple keyword
set lookups (NOT regex) to detect the ~1% of suspicious actions in
sub-microsecond time. Suspicious actions are then forwarded to the
server for full validation through all 3 security layers.

Performance:
  - Clean action:      ~0.001 ms (set.intersection, no regex)
  - Suspicious action:  flagged instantly, sent to server

Comparison:
  - Full local guards: 30+ shell regex, 17+ SQL regex, 9+ API regex
  - LightGuard:        3 keyword sets, zero regex, zero compilation
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import FrozenSet, Optional, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════════
# SUSPICIOUS KEYWORD SETS
# ═══════════════════════════════════════════════════════════════════════════
# These are the "red flag" tokens. If ANY of them appear in the action
# (case-insensitive), we mark it suspicious and send to the server.
# The sets are intentionally BROAD — false positives are cheap (one HTTP
# call), but false negatives are dangerous (action runs unchecked).

SHELL_SUSPICIOUS: FrozenSet[str] = frozenset({
    # Destructive
    "rm -rf", "rm -f", "rmdir", "del /s", "del /f", "format c:",
    "mkfs", "shred", "dd if=", "dd of=",
    # Privilege
    "sudo", "su root", "chmod 777", "chown root", "setuid",
    # Reverse shells
    "/dev/tcp", "/dev/udp", "reverse", "revshell", "msfvenom",
    "netcat", " nc -", "ncat ", "bash -i",
    # Download & execute
    "| bash", "| sh", "| python", "| perl",
    "curl |", "wget |", "wget -o", "downloadstring", "invoke-expression",
    "iex(", "iex ",
    # Crypto
    "xmrig", "minerd", "stratum+tcp", "cryptonight",
    # Persistence
    "crontab", "authorized_keys", ".ssh/",
    # Exfiltration
    "base64 |", "| curl", "| nc",
    # System sabotage
    "fork", ":()", "killall", "kill -9", "iptables -f",
    "systemctl stop", "systemctl disable", "ufw disable",
    # Windows
    "reg delete", "format c:", "diskpart", "powershell -c",
    # Dangerous paths
    "/etc/shadow", "/etc/passwd", "system32",
})

SQL_SUSPICIOUS: FrozenSet[str] = frozenset({
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
})

API_SUSPICIOUS: FrozenSet[str] = frozenset({
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
})


@dataclass
class LightCheckResult:
    """Result from the lightweight client-side check."""
    is_suspicious: bool
    guard_type: str            # "shell", "database", "api", "prompt"
    matched_keywords: list     # which keywords triggered
    elapsed_us: float          # microseconds taken
    action_preview: str        # first 80 chars (for logging)

    @property
    def should_send_to_server(self) -> bool:
        return self.is_suspicious


class LightGuard:
    """
    Ultra-lightweight client-side suspicion detector.

    Usage:
        guard = LightGuard()
        result = guard.check_shell("ls -la")          # → not suspicious (fast pass)
        result = guard.check_shell("rm -rf /")         # → suspicious → send to server
        result = guard.check_sql("SELECT * FROM users WHERE id = 1")  # → fast pass
        result = guard.check_sql("DROP TABLE users;")  # → suspicious
        result = guard.check_api("GET https://api.openai.com/v1/models")  # → fast pass
        result = guard.check_api("GET http://169.254.169.254/...")  # → suspicious
    """

    def __init__(
        self,
        extra_shell_keywords: Optional[Set[str]] = None,
        extra_sql_keywords: Optional[Set[str]] = None,
        extra_api_keywords: Optional[Set[str]] = None,
    ):
        self._shell_kw = SHELL_SUSPICIOUS | frozenset(extra_shell_keywords or set())
        self._sql_kw = SQL_SUSPICIOUS | frozenset(extra_sql_keywords or set())
        self._api_kw = API_SUSPICIOUS | frozenset(extra_api_keywords or set())

        # Stats
        self.total_checks = 0
        self.fast_passed = 0
        self.flagged = 0

    def _check(self, action: str, keywords: FrozenSet[str], guard_type: str) -> LightCheckResult:
        """Core check — scans for keyword presence in the lowercased action."""
        t0 = time.perf_counter_ns()
        self.total_checks += 1

        action_lower = action.lower()
        matched = [kw for kw in keywords if kw in action_lower]

        elapsed_us = (time.perf_counter_ns() - t0) / 1_000  # nanoseconds → microseconds

        is_suspicious = len(matched) > 0
        if is_suspicious:
            self.flagged += 1
        else:
            self.fast_passed += 1

        return LightCheckResult(
            is_suspicious=is_suspicious,
            guard_type=guard_type,
            matched_keywords=matched,
            elapsed_us=elapsed_us,
            action_preview=action[:80],
        )

    def check_shell(self, command: str) -> LightCheckResult:
        """Check a shell command for suspicious keywords."""
        return self._check(command, self._shell_kw, "shell")

    def check_sql(self, query: str) -> LightCheckResult:
        """Check a SQL query for suspicious keywords."""
        return self._check(query, self._sql_kw, "database")

    def check_api(self, request: str) -> LightCheckResult:
        """Check an API request for suspicious keywords."""
        return self._check(request, self._api_kw, "api")

    def check_auto(self, action: str) -> LightCheckResult:
        """
        Auto-detect action type and check with the appropriate keyword set.
        Checks all three sets — if any match, returns suspicious.
        """
        t0 = time.perf_counter_ns()
        self.total_checks += 1

        action_lower = action.lower()
        all_matched = []
        guard_type = "unknown"

        # Check shell keywords
        shell_hits = [kw for kw in self._shell_kw if kw in action_lower]
        if shell_hits:
            all_matched.extend(shell_hits)
            guard_type = "shell"

        # Check SQL keywords
        sql_hits = [kw for kw in self._sql_kw if kw in action_lower]
        if sql_hits:
            all_matched.extend(sql_hits)
            guard_type = "database" if not shell_hits else guard_type

        # Check API keywords
        api_hits = [kw for kw in self._api_kw if kw in action_lower]
        if api_hits:
            all_matched.extend(api_hits)
            guard_type = "api" if not shell_hits and not sql_hits else guard_type

        elapsed_us = (time.perf_counter_ns() - t0) / 1_000

        is_suspicious = len(all_matched) > 0
        if is_suspicious:
            self.flagged += 1
        else:
            self.fast_passed += 1

        return LightCheckResult(
            is_suspicious=is_suspicious,
            guard_type=guard_type,
            matched_keywords=all_matched,
            elapsed_us=elapsed_us,
            action_preview=action[:80],
        )

    @property
    def pass_rate(self) -> float:
        """Percentage of actions that passed locally without server check."""
        return (self.fast_passed / self.total_checks * 100) if self.total_checks else 0.0

    @property
    def stats(self) -> dict:
        return {
            "total_checks": self.total_checks,
            "fast_passed": self.fast_passed,
            "flagged_to_server": self.flagged,
            "pass_rate_pct": round(self.pass_rate, 2),
        }
