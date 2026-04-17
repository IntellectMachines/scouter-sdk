"""
APIGuard — Intercepts outbound HTTP/API requests before execution.

Catches: SSRF to cloud metadata, webhook exfiltration, path traversal,
requests to internal networks, auth token leaks.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from scouter.guards.base import BaseGuard, GuardDecision, GuardResult

API_RULES: List[Dict[str, Any]] = [
    {"name": "aws_metadata",     "pattern": r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com", "risk": 95, "desc": "Cloud metadata SSRF"},
    {"name": "internal_net",     "pattern": r"(?:^|\/|@)(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.0\.0\.1|localhost)", "risk": 70, "desc": "Internal/private network"},
    {"name": "delete_admin",     "pattern": r"DELETE.*(?:/admin|/users|/accounts|/database|/system|/config)", "risk": 90, "desc": "DELETE on admin endpoint"},
    {"name": "put_secrets",      "pattern": r"PUT.*(?:/config|/settings|/environment|/\.env|/secrets)", "risk": 80, "desc": "PUT modifying config/secrets"},
    {"name": "webhook_exfil",    "pattern": r"(?:webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|burpcollaborator)", "risk": 85, "desc": "Known exfiltration service"},
    {"name": "ngrok_tunnel",     "pattern": r"\.ngrok\.io|\.ngrok\.app|\.trycloudflare\.com", "risk": 75, "desc": "Tunnel service — exfiltration risk"},
    {"name": "pastebin_upload",  "pattern": r"(?:pastebin\.com|hastebin\.com|paste\.ee|ghostbin)", "risk": 80, "desc": "Paste service upload"},
    {"name": "path_traversal",   "pattern": r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/){2,}", "risk": 90, "desc": "Path traversal in URL"},
    {"name": "cred_in_url",      "pattern": r"(?:api_key|token|secret|password|auth)\s*[=:]\s*['\"]?\w{8,}", "risk": 85, "desc": "Credentials in request"},
]


class APIGuard(BaseGuard):
    """Intercepts outbound HTTP/API requests."""

    guard_type = "api"

    def __init__(
        self, mode: str = "enforce",
        custom_rules: Optional[List[Dict[str, Any]]] = None,
        allowed_domains: Optional[List[str]] = None,
        blocked_domains: Optional[List[str]] = None,
    ):
        super().__init__(mode=mode, custom_rules=custom_rules)
        self.allowed_domains = [d.lower() for d in (allowed_domains or [])]
        self.blocked_domains = [d.lower() for d in (blocked_domains or [])]
        self._compiled = []
        for rule in API_RULES + (custom_rules or []):
            try:
                self._compiled.append({
                    "name": rule["name"], "risk": rule["risk"], "desc": rule["desc"],
                    "_re": re.compile(rule["pattern"], re.IGNORECASE),
                })
            except re.error:
                pass

    def analyze(self, action: str, context: Dict[str, Any]) -> GuardResult:
        parts = action.strip().split(None, 1)
        if len(parts) == 2 and parts[0].upper() in ("GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"):
            method, url = parts[0].upper(), parts[1]
        else:
            method, url = context.get("method", "GET").upper(), action.strip()

        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            domain = (parsed.hostname or "").lower()
        except Exception:
            domain = ""

        # Domain whitelist
        if self.allowed_domains and domain:
            if not any(domain == d or domain.endswith(f".{d}") for d in self.allowed_domains):
                return GuardResult(
                    decision=GuardDecision.BLOCK, guard_type=self.guard_type, action=action,
                    reason=f"Domain '{domain}' not in allowed list", risk_score=75.0,
                    matched_rules=["domain_not_allowed"],
                )

        # Domain blocklist
        if domain and any(domain == d or domain.endswith(f".{d}") for d in self.blocked_domains):
            return GuardResult(
                decision=GuardDecision.BLOCK, guard_type=self.guard_type, action=action,
                reason=f"Domain '{domain}' is blocked", risk_score=90.0,
                matched_rules=["domain_blocked"],
            )

        full_action = f"{method} {url}"
        matched = []
        max_risk = 0.0
        for rule in self._compiled:
            if rule["_re"].search(full_action):
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
            reason=f"Matched {len(matched)} rule(s): {', '.join(matched)}" if matched else "Request appears safe",
            risk_score=max_risk, matched_rules=matched,
        )
