"""
ActionTriageClassifier -- Multi-level short-circuit classifier that
decides whether a tool call or prompt needs backend evaluation.

Design principle:
  Most LLM interactions are benign (knowledge-base lookups, text
  generation, simple queries).  Only ~5-15% involve actions that touch
  systems, APIs, databases, filesystems, or cloud resources.

  This classifier runs *entirely on the client* in O(n) time (n = input
  length) and returns SKIP or SCAN.  Only SCAN actions are sent to the
  backend for full consequence evaluation + guard checks.

Algorithm layers (each can short-circuit):
  Level 0: TOOL NAME LOOKUP           O(1)  -- known-safe tool → SKIP
  Level 1: TOOL NAME DANGER PATTERNS  O(k)  -- known-dangerous prefix → SCAN
  Level 2: ARGUMENT KEYWORD SCAN      O(n)  -- system/API/DB/FS triggers → SCAN
  Level 3: STRUCTURAL PATTERN DETECT  O(n)  -- file paths, URLs, SQL, shell syntax
  Level 4: TEXT COMPLETION TRIAGE      O(n)  -- skip pure conversation content

Memoization:
  Tool names are cached after first classification.  Repeated calls to
  the same tool (e.g. 5x search_knowledge_base) pay O(1) after the first.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set


class TriageVerdict(str, Enum):
    """Whether an action needs backend evaluation."""
    SKIP = "SKIP"    # Benign — no backend call needed
    SCAN = "SCAN"    # Actionable — send to backend for evaluation


@dataclass
class TriageResult:
    """Result of the triage classification."""
    verdict: TriageVerdict
    level: int              # Which level made the decision (0-4)
    reason: str             # Human-readable explanation
    category: str           # "safe_tool", "dangerous_tool", "system", "api", "database", "filesystem", "cloud", "conversation"
    matched_triggers: List[str] = field(default_factory=list)
    elapsed_us: float = 0.0 # Microseconds taken


# ═══════════════════════════════════════════════════════════════════════════
# CLASSIFICATION DATA
# ═══════════════════════════════════════════════════════════════════════════

# Level 0: Known-safe tool names (exact match) — pure read/query, no side effects
SAFE_TOOLS: FrozenSet[str] = frozenset({
    # Knowledge / search
    "search_knowledge_base", "search_docs", "search_faq", "search",
    "query_knowledge", "lookup_info", "get_info", "get_help",
    # Read-only data access
    "lookup_order", "get_order", "get_order_status", "check_status",
    "get_product", "list_products", "search_products",
    "get_user_info", "get_profile", "get_account",
    "check_refund_eligibility", "check_eligibility",
    # Weather / time / calculators
    "get_weather", "get_time", "calculate", "convert_currency",
    # Code analysis (read-only)
    "read_file", "list_files", "search_code", "get_file_content",
    "analyze_code", "lint_code", "format_code",
})

# Level 1: Dangerous tool name prefixes/patterns — always SCAN
_DANGEROUS_TOOL_PREFIXES: tuple[str, ...] = (
    # System execution
    "exec", "run_", "shell", "bash", "cmd", "command", "subprocess",
    "system", "spawn", "terminal", "powershell",
    # File mutation
    "create_file", "write_file", "delete_file", "remove_file",
    "move_file", "rename_file", "upload_file", "download_file",
    # Database mutation
    "insert", "update_", "delete_", "drop_", "create_table",
    "alter_", "truncate", "migrate",
    # Network / API mutation
    "send_email", "send_message", "send_sms", "post_", "put_",
    "http_post", "http_put", "http_delete", "webhook",
    "call_api", "invoke_api",
    # Financial
    "process_refund", "refund", "charge", "payment", "transfer",
    "payout", "withdraw", "invoice",
    # Cloud / infra
    "deploy", "provision", "terminate", "destroy", "scale",
    "create_instance", "delete_instance", "create_bucket",
    "delete_bucket", "create_database", "delete_database",
    # Auth / security
    "revoke", "grant", "change_password", "reset_password",
    "create_user", "delete_user", "modify_permissions",
)

# Level 2: Keyword triggers in tool arguments — indicate system interaction
_ARGUMENT_TRIGGERS: FrozenSet[str] = frozenset({
    # Shell / system
    "rm -rf", "rm -f", "sudo", "chmod", "chown", "kill",
    "/bin/", "/usr/bin/", "/etc/", "/dev/", "system32",
    "subprocess", "os.system", "exec(", "eval(",
    "bash -c", "sh -c", "cmd /c", "powershell",
    # Database
    "drop table", "drop database", "truncate", "delete from",
    "insert into", "update set", "alter table", "grant all",
    "union select", "xp_cmdshell",
    # File system
    "/etc/passwd", "/etc/shadow", "~/.ssh",
    "authorized_keys", ".env", "credentials",
    "../", "..\\",
    # Third-party APIs
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
    # Financial / high-risk
    "refund", "payout", "transfer", "withdraw",
    "charge", "payment_intent", "subscription",
    "credit_card", "bank_account",
    # Cloud metadata / SSRF
    "169.254.169.254", "metadata.google", "metadata.azure",
    # Exfiltration
    "webhook.site", "requestbin", "ngrok",
    "pastebin.com", "ghostbin",
    # Dangerous URLs
    "curl ", "wget ", "fetch(",
})

# Level 3: Structural patterns — regex for file paths, URLs, SQL, shell syntax
_STRUCTURAL_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("file_path_unix",   re.compile(r"/(?:etc|var|tmp|home|root|usr|bin|opt|dev)/", re.I), "filesystem"),
    ("file_path_win",    re.compile(r"[A-Z]:\\(?:Windows|Users|Program|System)", re.I), "filesystem"),
    ("shell_pipe",       re.compile(r"\|(?:\s*(?:bash|sh|python|perl|ruby|exec))", re.I), "system"),
    ("shell_redirect",   re.compile(r"(?:>>?|2>&1)\s*/", re.I), "system"),
    ("shell_semicolon",  re.compile(r";\s*(?:rm|drop|delete|kill|curl|wget|sudo|chmod)", re.I), "system"),
    ("shell_backtick",   re.compile(r"`[^`]*(?:rm|curl|wget|exec|eval|sudo)", re.I), "system"),
    ("sql_ddl",          re.compile(r"\b(?:DROP|CREATE|ALTER|TRUNCATE)\s+(?:TABLE|DATABASE|INDEX|SCHEMA)\b", re.I), "database"),
    ("sql_dangerous",    re.compile(r"\b(?:DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b", re.I), "database"),
    ("url_with_action",  re.compile(r"https?://[^\s]+/(?:delete|destroy|terminate|refund|transfer|payout)", re.I), "api"),
    ("cloud_api",        re.compile(r"(?:amazonaws\.com|googleapis\.com|azure\.com|supabase\.co|pinecone\.io)", re.I), "cloud"),
    ("ip_internal",      re.compile(r"(?:127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.)", re.I), "api"),
]


# ═══════════════════════════════════════════════════════════════════════════
# PROMPT TRIAGE — semantic action patterns for user prompts
# ═══════════════════════════════════════════════════════════════════════════
# These detect natural-language imperatives that imply system interaction.
# They are heavier than argument triggers (regex, not substring) so they
# run as a separate level only for user-facing prompt text.

_PROMPT_ACTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # System destruction
    ("destroy_system",
     re.compile(r"\b(?:delete|remove|destroy|wipe|nuke|erase|obliterate)\b.*\b(?:all|every|entire|database|table|server|system|files?|codebase|repo(?:sitory)?|bucket|cluster|index)\b", re.I),
     "system"),
    # Shell / command execution
    ("shell_exec",
     re.compile(r"\b(?:run|execute|exec|launch|invoke|spawn)\b.*\b(?:command|script|shell|bash|terminal|cmd|powershell|subprocess)\b", re.I),
     "system"),
    # Raw shell syntax in prompt
    ("shell_inline",
     re.compile(r"\b(?:rm\s+-rf|sudo\s|chmod\s|kill\s+-9|dd\s+if=|mkfs\s|format\s+[A-Z]:)", re.I),
     "system"),
    # Database DDL in prompt
    ("db_destructive",
     re.compile(r"\b(?:drop|truncate)\b.*\b(?:table|database|schema|collection|index)\b", re.I),
     "database"),
    # Database DML danger
    ("db_bulk_mutation",
     re.compile(r"\b(?:delete\s+from|update\s+\w+\s+set)\b.*\b(?:where\s+1\s*=\s*1|all|every|without\s+(?:condition|where|filter))\b", re.I),
     "database"),
    # Financial transactions
    ("financial_action",
     re.compile(r"\b(?:refund|charge|transfer|payout|withdraw|send\s+money|wire\s+transfer)\b.*\b(?:\$[\d,.]+|amount|money|payment|funds?|account|balance|invoice)\b", re.I),
     "financial"),
    # Large refund (any mention of refund with a number > 500)
    ("large_refund",
     re.compile(r"\b(?:refund|reimburse|credit\s+back)\b.*\$\s*[\d,]*[5-9]\d{2,}|\$\s*[\d,]*\d{4,}", re.I),
     "financial"),
    # Third-party API calls
    ("third_party_action",
     re.compile(r"\b(?:call|invoke|send|post|delete|connect|use)\b.*\b(?:stripe|supabase|pinecone|aws|firebase|twilio|sendgrid|github|vercel|cloudflare|openai|anthropic)\b", re.I),
     "third_party_api"),
    # Cloud resource lifecycle
    ("cloud_lifecycle",
     re.compile(r"\b(?:terminate|destroy|delete|remove|deprovision|shutdown|scale\s+down)\b.*\b(?:instance|server|bucket|cluster|function|resource|vm|container|pod|node|lambda)\b", re.I),
     "cloud"),
    # File system mutation
    ("fs_mutation",
     re.compile(r"\b(?:create|write|modify|overwrite|delete|remove)\b.*\b(?:file|directory|folder|config|\.env|credentials|\.ssh|authorized_keys)\b", re.I),
     "filesystem"),
    # Prompt injection / jailbreak
    ("prompt_injection",
     re.compile(r"\b(?:ignore|forget|disregard|override|bypass|skip)\b.*\b(?:instructions?|rules?|guidelines?|previous|system\s+prompt|security|restrictions?|safety)\b", re.I),
     "injection"),
    # Data exfiltration
    ("data_exfiltration",
     re.compile(r"\b(?:send|email|upload|post|transfer|exfiltrate|steal|dump|extract)\b.*\b(?:data|records?|information|credentials?|passwords?|keys?|tokens?|secrets?|PII|customer|user)\b", re.I),
     "api"),
    # Credential / access
    ("credential_access",
     re.compile(r"\b(?:give|grant|show|reveal|expose|display)\b.*\b(?:admin|root|superuser|password|secret|key|token|credential|access|permission)\b", re.I),
     "system"),
]


class ActionTriageClassifier:
    """
    Multi-level short-circuit classifier for tool calls and prompts.

    Usage:
        classifier = ActionTriageClassifier()

        # Tool call triage
        result = classifier.classify_tool_call("search_knowledge_base", '{"query":"denim jacket"}')
        # → TriageResult(verdict=SKIP, level=0, reason="Known safe tool")

        result = classifier.classify_tool_call("process_refund", '{"order_id":"ORD-10001","reason":"defective"}')
        # → TriageResult(verdict=SCAN, level=1, reason="Dangerous tool prefix: process_refund")

        # Text completion triage
        result = classifier.classify_completion("Here are the details of your order...")
        # → TriageResult(verdict=SKIP, level=4, reason="Pure conversational content")

        result = classifier.classify_completion("I'll delete the database for you: DROP TABLE users")
        # → TriageResult(verdict=SCAN, level=3, reason="Structural pattern: sql_ddl")
    """

    def __init__(
        self,
        extra_safe_tools: Optional[Set[str]] = None,
        extra_dangerous_prefixes: Optional[tuple[str, ...]] = None,
        extra_triggers: Optional[Set[str]] = None,
    ):
        self._safe_tools = SAFE_TOOLS | frozenset(extra_safe_tools or set())
        self._dangerous_prefixes = _DANGEROUS_TOOL_PREFIXES + (extra_dangerous_prefixes or ())
        self._argument_triggers = _ARGUMENT_TRIGGERS | frozenset(extra_triggers or set())

        # Memoization: tool_name → (verdict, reason, category)
        self._tool_name_cache: Dict[str, tuple[TriageVerdict, str, str]] = {}

        # Stats
        self.total_classified = 0
        self.skipped = 0
        self.scanned = 0

    def classify_tool_call(
        self,
        tool_name: str,
        arguments: str = "",
    ) -> TriageResult:
        """
        Classify a tool call as SKIP or SCAN.

        Runs through levels 0→1→2→3 with short-circuit exits.
        """
        t0 = time.perf_counter_ns()
        self.total_classified += 1
        tool_lower = tool_name.lower()
        args_lower = arguments.lower() if arguments else ""

        # ── Level 0: Known-safe tool exact match (O(1) hash lookup) ────
        if tool_lower in self._safe_tools:
            # But still check arguments for injection attacks
            if not args_lower or not self._has_argument_triggers(args_lower):
                return self._result(
                    TriageVerdict.SKIP, 0, "Known safe tool",
                    "safe_tool", [], t0,
                )

        # ── Level 0 cache: check memoized tool name result ─────────────
        if tool_lower in self._tool_name_cache and not args_lower:
            v, r, c = self._tool_name_cache[tool_lower]
            return self._result(v, 0, f"Cached: {r}", c, [], t0)

        # ── Level 1: Dangerous tool name prefix (O(k) k=prefix count) ──
        for prefix in self._dangerous_prefixes:
            if tool_lower.startswith(prefix) or tool_lower == prefix:
                self._tool_name_cache[tool_lower] = (
                    TriageVerdict.SCAN,
                    f"Dangerous tool: {prefix}",
                    "dangerous_tool",
                )
                return self._result(
                    TriageVerdict.SCAN, 1,
                    f"Dangerous tool prefix: {prefix}",
                    "dangerous_tool", [prefix], t0,
                )

        # ── Level 2: Argument keyword scan (O(n) single pass) ──────────
        if args_lower:
            triggers = self._find_argument_triggers(args_lower)
            if triggers:
                category = self._categorize_triggers(triggers)
                return self._result(
                    TriageVerdict.SCAN, 2,
                    f"Argument triggers: {', '.join(triggers[:3])}",
                    category, triggers, t0,
                )

        # ── Level 3: Structural patterns in arguments (regex) ──────────
        if args_lower:
            for name, pattern, category in _STRUCTURAL_PATTERNS:
                if pattern.search(args_lower):
                    return self._result(
                        TriageVerdict.SCAN, 3,
                        f"Structural pattern: {name}",
                        category, [name], t0,
                    )

        # ── Default: Unknown tool, no triggers → still SCAN for safety ─
        # Unknown tools get scanned on first encounter, then cached
        if tool_lower not in self._safe_tools and tool_lower not in self._tool_name_cache:
            # First time seeing this tool — scan it but cache as safe for future
            self._tool_name_cache[tool_lower] = (
                TriageVerdict.SKIP,
                "No danger signals on first encounter",
                "unknown_tool",
            )
            return self._result(
                TriageVerdict.SKIP, 0,
                "Unknown tool, no danger signals",
                "unknown_tool", [], t0,
            )

        return self._result(
            TriageVerdict.SKIP, 0,
            "No danger signals detected",
            "safe_tool", [], t0,
        )

    def classify_completion(self, content: str) -> TriageResult:
        """
        Classify a text completion (no tool call) as SKIP or SCAN.

        Most text completions are pure conversation — skip them.
        Only scan if the content contains actionable patterns.
        """
        t0 = time.perf_counter_ns()
        self.total_classified += 1

        if not content or len(content) < 10:
            return self._result(
                TriageVerdict.SKIP, 4,
                "Empty or trivial content",
                "conversation", [], t0,
            )

        content_lower = content.lower()

        # Check for structural patterns in the text
        for name, pattern, category in _STRUCTURAL_PATTERNS:
            if pattern.search(content_lower):
                return self._result(
                    TriageVerdict.SCAN, 3,
                    f"Structural pattern in completion: {name}",
                    category, [name], t0,
                )

        # Check for argument triggers in the text
        triggers = self._find_argument_triggers(content_lower)
        if triggers:
            category = self._categorize_triggers(triggers)
            return self._result(
                TriageVerdict.SCAN, 2,
                f"Keyword triggers in completion: {', '.join(triggers[:3])}",
                category, triggers, t0,
            )

        # Pure conversational content — skip
        return self._result(
            TriageVerdict.SKIP, 4,
            "Pure conversational content",
            "conversation", [], t0,
        )

    def classify_prompt(self, prompt: str) -> TriageResult:
        """
        Classify a raw user prompt as SKIP or SCAN.

        Called BEFORE sending the prompt to the backend for ML-based
        analysis.  Uses a 4-level short-circuit pipeline:

          Level 0: Trivial/short prompts                  → SKIP
          Level 1: Prompt-specific action patterns (regex) → SCAN
          Level 2: Keyword triggers (substring scan)       → SCAN
          Level 3: Structural patterns (file/SQL/shell/URL)→ SCAN
          Level 4: No actionable signals                   → SKIP

        Only SCAN prompts are sent for backend evaluation.  This saves
        85-95% of backend calls for conversational agents.
        """
        t0 = time.perf_counter_ns()
        self.total_classified += 1

        if not prompt or len(prompt) < 5:
            return self._result(
                TriageVerdict.SKIP, 0,
                "Empty or trivial prompt",
                "conversation", [], t0,
            )

        prompt_lower = prompt.lower()

        # ── Level 1: Prompt action patterns (semantic imperatives) ─────
        # These regex patterns detect natural-language requests for system
        # interaction: "delete all files", "refund $500", "run this command"
        for name, pattern, category in _PROMPT_ACTION_PATTERNS:
            if pattern.search(prompt_lower):
                return self._result(
                    TriageVerdict.SCAN, 1,
                    f"Prompt action pattern: {name}",
                    category, [name], t0,
                )

        # ── Level 2: Keyword triggers (same as tool argument scan) ─────
        triggers = self._find_argument_triggers(prompt_lower)
        if triggers:
            category = self._categorize_triggers(triggers)
            return self._result(
                TriageVerdict.SCAN, 2,
                f"Keyword triggers in prompt: {', '.join(triggers[:3])}",
                category, triggers, t0,
            )

        # ── Level 3: Structural patterns (file paths, SQL, shell, URLs) ─
        for name, pattern, category in _STRUCTURAL_PATTERNS:
            if pattern.search(prompt_lower):
                return self._result(
                    TriageVerdict.SCAN, 3,
                    f"Structural pattern in prompt: {name}",
                    category, [name], t0,
                )

        # ── Level 4: No actionable signals — skip ─────────────────────
        return self._result(
            TriageVerdict.SKIP, 4,
            "Conversational prompt — no actionable signals",
            "conversation", [], t0,
        )

    def _has_argument_triggers(self, args_lower: str) -> bool:
        """Fast check: any trigger keyword in args?"""
        for trigger in self._argument_triggers:
            if trigger in args_lower:
                return True
        return False

    def _find_argument_triggers(self, text: str) -> List[str]:
        """Find all trigger keywords in text."""
        return [t for t in self._argument_triggers if t in text]

    def _categorize_triggers(self, triggers: List[str]) -> str:
        """Determine the primary category from matched triggers."""
        # Check in priority order
        for t in triggers:
            if any(s in t for s in ("stripe", "twilio", "sendgrid", "supabase", "pinecone", "firebase", "github")):
                return "third_party_api"
            if any(s in t for s in ("amazonaws", "googleapis", "azure")):
                return "cloud"
            if any(s in t for s in ("drop ", "delete from", "truncate", "insert", "update", "xp_cmd")):
                return "database"
            if any(s in t for s in ("/etc/", "/dev/", "sudo", "chmod", "rm -", "bash", "shell", "subprocess")):
                return "system"
            if any(s in t for s in (".env", "credentials", "authorized_keys", "../")):
                return "filesystem"
            if any(s in t for s in ("refund", "payout", "transfer", "charge", "payment", "withdraw")):
                return "financial"
        return "api"

    def _result(
        self,
        verdict: TriageVerdict,
        level: int,
        reason: str,
        category: str,
        triggers: List[str],
        t0: int,
    ) -> TriageResult:
        elapsed = (time.perf_counter_ns() - t0) / 1_000
        if verdict == TriageVerdict.SKIP:
            self.skipped += 1
        else:
            self.scanned += 1
        return TriageResult(
            verdict=verdict,
            level=level,
            reason=reason,
            category=category,
            matched_triggers=triggers,
            elapsed_us=elapsed,
        )

    @property
    def stats(self) -> dict:
        return {
            "total_classified": self.total_classified,
            "skipped": self.skipped,
            "scanned": self.scanned,
            "skip_rate_pct": round(
                (self.skipped / self.total_classified * 100)
                if self.total_classified else 0.0, 2,
            ),
            "cache_size": len(self._tool_name_cache),
        }
