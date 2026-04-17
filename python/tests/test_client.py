"""
Python SDK client tests — mirrors Node.js SDK test structure.
Tests ScouterClient, IntentRegistry, ConsequenceEngine, Guards, and BackendClient.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scouter import (
    ScouterClient,
    IntentRegistry,
    ConsequenceEngine,
    ActionTriageClassifier,
    ExecutionInterceptor,
    ShellGuard,
    DatabaseGuard,
    APIGuard,
    LightGuard,
    BackendClient,
    GuardDecision,
)
from scouter.models import ActionProposal, Decision, ActualExecution


# ── ScouterClient ────────────────────────────────────────────────────


class TestScouterClient:
    def test_initializes_with_defaults(self):
        client = ScouterClient(verbose=False)
        assert client.mode == "audit"
        assert client.trace_id.startswith("trace-")
        assert client.backend is None

    def test_initializes_with_backend_url(self):
        # Backend is unreachable, so it should fall back to local
        client = ScouterClient(
            api_key="test-key",
            backend_url="http://localhost:1",
            verbose=False,
        )
        assert client.backend is None  # unreachable → falls back
        assert client.interceptor is not None

    def test_generates_new_trace_ids(self):
        client = ScouterClient(verbose=False)
        t1 = client.trace_id
        t2 = client.new_trace()
        assert t1 != t2
        assert t2.startswith("trace-")

    def test_has_interceptor(self):
        client = ScouterClient(verbose=False)
        assert client.interceptor is not None

    def test_has_classifier(self):
        client = ScouterClient(verbose=False)
        assert isinstance(client.classifier, ActionTriageClassifier)


# ── IntentRegistry ───────────────────────────────────────────────────


class TestIntentRegistry:
    def test_register_and_retrieve(self):
        registry = IntentRegistry()
        intent = registry.register(
            agent_id="test-agent",
            intent="Process customer support tickets",
            permitted_actions=["lookup_order", "process_refund"],
            excluded_actions=["delete_customer"],
        )
        assert intent.agent_id == "test-agent"
        assert "lookup_order" in intent.permitted_actions
        assert "delete_customer" in intent.excluded_actions

        found = registry.get(intent.intent_id)
        assert found is not None
        assert found.natural_language == "Process customer support tickets"

    def test_get_by_agent(self):
        registry = IntentRegistry()
        intent = registry.register(
            agent_id="agent-abc",
            intent="Read data",
            permitted_actions=["read"],
        )
        found = registry.get_by_agent("agent-abc")
        assert found is not None
        assert found.intent_id == intent.intent_id

    def test_get_nonexistent_returns_none(self):
        registry = IntentRegistry()
        assert registry.get("nonexistent-id") is None
        assert registry.get_by_agent("nonexistent-agent") is None


# ── ConsequenceEngine ────────────────────────────────────────────────


class TestConsequenceEngine:
    def test_permitted_action_passes(self):
        client = ScouterClient(verbose=False)
        intent = client.registry.register(
            agent_id="test-agent",
            intent="Process customer support tickets",
            permitted_actions=["lookup_order", "process_refund"],
            excluded_actions=["delete_customer"],
        )
        result = client.engine.evaluate(
            ActionProposal(
                action_type="lookup_order",
                target_system="orders",
                payload_summary="Looking up order #1234",
                delegation_depth=0,
            ),
            intent,
        )
        assert result.evaluation.calculated_decision == Decision.PASS_THROUGH
        assert result.evaluation.actual_execution == ActualExecution.AUDIT_PASS

    def test_excluded_action_escalates(self):
        client = ScouterClient(verbose=False)
        intent = client.registry.register(
            agent_id="test-agent",
            intent="Process customer support tickets",
            permitted_actions=["lookup_order"],
            excluded_actions=["delete_customer"],
        )
        result = client.engine.evaluate(
            ActionProposal(
                action_type="delete_customer",
                target_system="crm",
                payload_summary="Deleting customer record",
                delegation_depth=0,
            ),
            intent,
        )
        # delete has high irreversibility (0.95) → ESCALATE
        assert result.evaluation.calculated_decision == Decision.ESCALATE

    def test_no_intent_moderate_score(self):
        engine = ConsequenceEngine()
        result = engine.evaluate(
            ActionProposal(
                action_type="read",
                target_system="db",
                payload_summary="Reading records",
                delegation_depth=0,
            ),
        )
        assert result.evaluation.irreversibility_score == 0.05
        assert result.evaluation.alignment_score == 0.50

    def test_delegation_depth_penalty(self):
        client = ScouterClient(verbose=False)
        intent = client.registry.register(
            agent_id="test",
            intent="Read files",
            permitted_actions=["read_file"],
        )
        result = client.engine.evaluate(
            ActionProposal(
                action_type="read_file",
                target_system="fs",
                payload_summary="config.json",
                delegation_depth=5,
            ),
            intent,
        )
        # With depth=5, penalty = min(0.4, 5 * 0.08) = 0.4
        # alignment 0.90 * (1 - 0.4) = 0.54
        assert result.evaluation.alignment_score < 0.90


# ── Guards ───────────────────────────────────────────────────────────


class TestShellGuard:
    def test_blocks_rm_rf(self):
        guard = ShellGuard(mode="enforce")
        result = guard.check("rm -rf /")
        assert result.decision == GuardDecision.BLOCK
        assert result.risk_score > 0

    def test_allows_safe_command(self):
        guard = ShellGuard(mode="enforce")
        result = guard.check("ls -la")
        assert result.decision == GuardDecision.ALLOW


class TestDatabaseGuard:
    def test_blocks_drop_table(self):
        guard = DatabaseGuard(mode="enforce")
        result = guard.check("DROP TABLE users")
        assert result.decision == GuardDecision.BLOCK

    def test_allows_select(self):
        guard = DatabaseGuard(mode="enforce")
        result = guard.check("SELECT id, name FROM users WHERE id = 1")
        assert result.decision == GuardDecision.ALLOW


class TestAPIGuard:
    def test_blocks_internal_ip(self):
        guard = APIGuard(mode="enforce")
        result = guard.check("GET http://169.254.169.254/latest/meta-data")
        assert result.decision == GuardDecision.BLOCK

    def test_allows_normal_api(self):
        guard = APIGuard(mode="enforce")
        result = guard.check("GET https://api.example.com/data")
        assert result.decision == GuardDecision.ALLOW


class TestLightGuard:
    def test_detects_suspicious_shell(self):
        guard = LightGuard()
        result = guard.check_shell("rm -rf / --no-preserve-root")
        assert result.is_suspicious

    def test_passes_benign_shell(self):
        guard = LightGuard()
        result = guard.check_shell("echo hello")
        assert not result.is_suspicious


class TestExecutionInterceptor:
    def test_audit_mode_downgrades(self):
        interceptor = ExecutionInterceptor(mode="audit", verbose=False)
        result = interceptor.check_shell("rm -rf /")
        # In audit mode, BLOCK → WARN
        assert result.decision in (GuardDecision.WARN, GuardDecision.ALLOW)

    def test_enforce_mode_blocks(self):
        interceptor = ExecutionInterceptor(mode="enforce", verbose=False)
        result = interceptor.check_shell("rm -rf /")
        assert result.decision == GuardDecision.BLOCK


# ── ActionTriageClassifier ───────────────────────────────────────────


class TestActionTriageClassifier:
    def test_safe_tool_skipped(self):
        classifier = ActionTriageClassifier()
        result = classifier.classify_tool_call("get_current_time", "{}")
        assert result.verdict == "SKIP"

    def test_dangerous_tool_scanned(self):
        classifier = ActionTriageClassifier()
        result = classifier.classify_tool_call("execute_command", '{"cmd": "rm -rf /"}')
        assert result.verdict == "SCAN"


# ── BackendClient ────────────────────────────────────────────────────


class TestBackendClient:
    def test_has_all_api_methods(self):
        client = BackendClient("http://localhost:1", api_key="test")
        methods = [
            "register_intent", "get_intent", "evaluate",
            "ingest_span", "analyze_trace",
            "verify_artifact", "export_compliance",
            "health",
            "get_telemetry_stats", "get_agent_telemetry",
            "get_agent_stats", "get_trace_telemetry",
            "analyze_prompt", "analyze_prompt_batch",
            "mint_credential", "revoke_credential", "validate_credential",
            "evaluate_pbac", "list_policies",
            "register_agent_did", "resolve_did", "revoke_did", "rotate_did_key",
        ]
        for method in methods:
            assert hasattr(client, method), f"Missing method: {method}"
            assert callable(getattr(client, method))

    def test_health_returns_false_on_unreachable(self):
        client = BackendClient("http://localhost:1", timeout=0.1)
        assert client.health() is False

    def test_evaluate_returns_none_on_unreachable(self):
        client = BackendClient("http://localhost:1", timeout=0.1)
        result = client.evaluate(
            {"action_type": "read", "target_system": "fs"},
            intent_id="test",
        )
        assert result is None

    def test_register_intent_returns_none_on_unreachable(self):
        client = BackendClient("http://localhost:1", timeout=0.1)
        result = client.register_intent(
            agent_id="test",
            natural_language="Test",
            permitted_actions=["read"],
            excluded_actions=[],
        )
        assert result is None
