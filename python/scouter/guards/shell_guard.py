"""
ShellGuard — Intercepts shell/subprocess commands before execution.

Catches: destructive commands, privilege escalation, data exfiltration,
reverse shells, crypto miners, fork bombs, and more.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from scouter.guards.base import BaseGuard, GuardDecision, GuardResult

SHELL_RULES: List[Dict[str, Any]] = [
    # ── Destructive ───────────────────────────────────────────────────────
    {"name": "rm_rf",           "pattern": r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+.*-[a-zA-Z]*f[a-zA-Z]*r|\brm\s+-rf\b", "risk": 95, "desc": "Recursive force delete"},
    {"name": "rm_root",         "pattern": r"\brm\b.*(?:\s+/\s|\s+/\*|\s+~|\s+\.\.\/)|\brm\b.*--no-preserve-root", "risk": 100, "desc": "Delete targeting root/home/parent"},
    {"name": "format_disk",     "pattern": r"\b(?:mkfs|format)\b.*(?:/dev/|[A-Z]:)", "risk": 100, "desc": "Disk format command"},
    {"name": "dd_wipe",         "pattern": r"\bdd\b.*\bof\s*=\s*/dev/(?:sd|hd|nvme|vd)", "risk": 95, "desc": "dd writing to block device"},
    {"name": "shred_wipe",      "pattern": r"\b(?:shred|wipe|srm|secure-delete)\b", "risk": 90, "desc": "Secure delete/wipe utility"},
    {"name": "truncate_dev",    "pattern": r">\s*/dev/(?:sd|hd)|cat\s+/dev/(?:null|zero|urandom)\s*>\s*/", "risk": 95, "desc": "Overwriting device with /dev/null"},

    # ── Privilege escalation ──────────────────────────────────────────────
    {"name": "sudo_su",         "pattern": r"\b(?:sudo|su\s+-|su\s+root|doas)\b", "risk": 60, "desc": "Privilege escalation via sudo/su"},
    {"name": "chmod_777",       "pattern": r"\bchmod\b.*(?:777|u\+s|g\+s|\+s|4755|2755)", "risk": 75, "desc": "Dangerous permissions (777/SUID)"},
    {"name": "passwd_shadow",   "pattern": r"\b(?:cat|less|more|head|tail|vi|vim|nano)\b.*(?:/etc/passwd|/etc/shadow)", "risk": 80, "desc": "Reading password/shadow files"},

    # ── Data exfiltration ─────────────────────────────────────────────────
    {"name": "curl_post",       "pattern": r"\bcurl\b.*(?:-d\b|-X\s*POST|--data).*(?:http|https)", "risk": 70, "desc": "curl POSTing data externally"},
    {"name": "wget_pipe_exec",  "pattern": r"\bwget\b.*-O\s*-\s*\||\bcurl\b.*\|\s*(?:bash|sh|python|perl|ruby)", "risk": 90, "desc": "Download and pipe to interpreter"},
    {"name": "netcat",          "pattern": r"\b(?:nc|ncat|netcat)\b.*(?:-l|-e\s*/bin|mkfifo)", "risk": 90, "desc": "Netcat listener/reverse shell"},
    {"name": "exfil_encode",    "pattern": r"\bbase64\b.*\|\s*(?:curl|wget|nc)", "risk": 85, "desc": "Encoding + sending to external host"},

    # ── Reverse shells ────────────────────────────────────────────────────
    {"name": "bash_revshell",   "pattern": r"(?:bash|sh)\s+-i\s*>(?:&|\s)\s*/dev/tcp/", "risk": 100, "desc": "Bash reverse shell via /dev/tcp"},
    {"name": "python_revshell", "pattern": r"python[23]?\s+-c\s*['\"].*(?:socket|subprocess|pty\.spawn)", "risk": 100, "desc": "Python reverse shell"},
    {"name": "perl_revshell",   "pattern": r"perl\s+-e\s*['\"].*(?:socket|exec|fork)", "risk": 95, "desc": "Perl reverse shell"},
    {"name": "php_revshell",    "pattern": r"php\s+-r\s*['\"].*(?:fsockopen|exec|shell_exec|system)", "risk": 95, "desc": "PHP reverse shell"},

    # ── Malware / persistence ─────────────────────────────────────────────
    {"name": "crypto_miner",    "pattern": r"\b(?:xmrig|minerd|cgminer|bfgminer|cpuminer|stratum\+tcp)\b", "risk": 90, "desc": "Cryptocurrency miner"},
    {"name": "cron_persist",    "pattern": r"\b(?:crontab\s+-e|echo\b.*>.*crontab|/etc/cron)", "risk": 70, "desc": "Cron persistence mechanism"},
    {"name": "ssh_key_inject",  "pattern": r">>?\s*~?/?\.ssh/authorized_keys", "risk": 85, "desc": "SSH key injection"},
    {"name": "fork_bomb",       "pattern": r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;", "risk": 100, "desc": "Fork bomb"},

    # ── System sabotage ──────────────────────────────────────────────────
    {"name": "iptables_flush",  "pattern": r"\biptables\b.*-F|\biptables\b.*--flush|\bufw\s+disable\b", "risk": 80, "desc": "Flushing firewall rules"},
    {"name": "kill_all",        "pattern": r"\bkillall\b|\bkill\s+-9\s+-1\b|\bpkill\s+-9\b", "risk": 75, "desc": "Mass process killing"},
    {"name": "svc_disable",     "pattern": r"\bsystemctl\b.*(?:disable|stop|mask).*(?:firewall|ufw|iptables|sshd|fail2ban)", "risk": 85, "desc": "Disabling security services"},

    # ── Windows-specific ─────────────────────────────────────────────────
    {"name": "win_format",      "pattern": r"\bformat\b.*[A-Z]:\s*/[yY]|\bdiskpart\b", "risk": 95, "desc": "Windows disk format/diskpart"},
    {"name": "win_reg_delete",  "pattern": r"\breg\b.*(?:delete|add).*(?:HKLM|HKCU|HKCR).*\/f", "risk": 85, "desc": "Windows registry deletion"},
    {"name": "ps_download_exec","pattern": r"(?:powershell|pwsh).*(?:IEX|Invoke-Expression|DownloadString|DownloadFile).*http", "risk": 90, "desc": "PowerShell download-and-execute"},
    {"name": "win_del_recurse", "pattern": r"\bdel\b.*\/[sS].*\/[fFqQ]|\brmdir\b.*\/[sS].*\/[qQ]", "risk": 90, "desc": "Windows recursive force delete"},
]


class ShellGuard(BaseGuard):
    """Intercepts shell commands before execution."""

    guard_type = "shell"

    def __init__(self, mode: str = "enforce", custom_rules: Optional[List[Dict[str, Any]]] = None):
        super().__init__(mode=mode, custom_rules=custom_rules)
        self._compiled = []
        for rule in SHELL_RULES + (custom_rules or []):
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
        cmd = action.strip()
        matched = []
        max_risk = 0.0

        for rule in self._compiled:
            if rule["_re"].search(cmd):
                matched.append(rule["name"])
                max_risk = max(max_risk, rule["risk"])

        if max_risk >= 80:
            decision = GuardDecision.BLOCK
        elif max_risk >= 40:
            decision = GuardDecision.WARN
        else:
            decision = GuardDecision.ALLOW

        return GuardResult(
            decision=decision,
            guard_type=self.guard_type,
            action=action,
            reason=f"Matched {len(matched)} rule(s): {', '.join(matched)}" if matched else "No dangerous patterns detected",
            risk_score=max_risk,
            matched_rules=matched,
        )
