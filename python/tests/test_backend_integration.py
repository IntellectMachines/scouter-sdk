"""
SDK ↔ Backend integration tests.

Spins up the FastAPI backend via TestClient and runs the SDK's
BackendClient against it to verify the full round-trip.
"""

import os
import sys
import shutil
import tempfile
import pytest

# Add backend to path so we can import the app
backend_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "backend")
sys.path.insert(0, backend_dir)

# Temp DB for isolation
tmp_dir = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tmp_dir, 'test_sdk.db')}"
os.environ["AUDIT_STORAGE_DIR"] = os.path.join(tmp_dir, "audit")
os.environ["SCOUTER_ENV"] = "dev"

from app.main import app
from app.database import init_db

init_db()

from fastapi.testclient import TestClient

# Use httpx transport to route SDK's BackendClient through TestClient
test_client = TestClient(app)

# Add SDK to path
sdk_dir = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, sdk_dir)

from scouter.api.backend import BackendClient


@pytest.fixture(scope="session", autouse=True)
def _cleanup():
    yield
    shutil.rmtree(tmp_dir, ignore_errors=True)


@pytest.fixture(scope="module")
def sdk():
    """BackendClient wired to the test server."""
    return BackendClient(
        base_url="http://testserver",
        client=test_client,
    )


class TestSDKIntentLifecycle:
    def test_register_intent(self, sdk):
        result = sdk.register_intent(
            agent_id="sdk-test-agent",
            natural_language="Manage customer orders and process refunds",
            permitted_actions=["lookup_order", "process_refund"],
            excluded_actions=["delete_customer"],
        )
        assert result is not None
        assert "intent_id" in result
        assert result["agent_id"] == "sdk-test-agent"

    def test_get_intent(self, sdk):
        # Register first
        created = sdk.register_intent(
            agent_id="sdk-test-agent-2",
            natural_language="Read configuration files",
            permitted_actions=["read_file"],
            excluded_actions=["delete_file"],
        )
        intent_id = created["intent_id"]

        # Retrieve
        fetched = sdk.get_intent(intent_id)
        assert fetched is not None
        assert fetched["intent_id"] == intent_id
        assert fetched["agent_id"] == "sdk-test-agent-2"


class TestSDKConsequenceEngine:
    def test_evaluate_permitted_action(self, sdk):
        # Register intent
        intent = sdk.register_intent(
            agent_id="sdk-eval-agent",
            natural_language="Read and list files in the workspace",
            permitted_actions=["read_file", "list_files"],
            excluded_actions=["delete_file"],
        )
        intent_id = intent["intent_id"]

        # Evaluate a permitted action (low irreversibility + explicit match)
        result = sdk.evaluate(
            action={
                "action_type": "read_file",
                "target_system": "filesystem",
                "payload_summary": "Reading config.json",
            },
            intent_id=intent_id,
        )
        assert result is not None
        assert result["evaluation"]["calculated_decision"] == "PASS_THROUGH"
        assert result["evaluation"]["actual_execution"] == "AUDIT_PASS"

    def test_evaluate_excluded_action(self, sdk):
        intent = sdk.register_intent(
            agent_id="sdk-eval-agent-2",
            natural_language="Read-only file access",
            permitted_actions=["read_file"],
            excluded_actions=["delete"],
        )
        intent_id = intent["intent_id"]

        result = sdk.evaluate(
            action={
                "action_type": "delete:records",
                "target_system": "database",
                "payload_summary": "DROP TABLE users",
            },
            intent_id=intent_id,
        )
        assert result is not None
        assert result["evaluation"]["calculated_decision"] in ("HARD_STOP", "ESCALATE")
        assert result["evaluation"]["irreversibility_score"] >= 0.9


class TestSDKAudit:
    def test_verify_artifact(self, sdk):
        # Create an evaluation to get an artifact
        intent = sdk.register_intent(
            agent_id="sdk-audit-agent",
            natural_language="Create workspace files",
            permitted_actions=["create_file"],
            excluded_actions=[],
        )
        eval_result = sdk.evaluate(
            action={
                "action_type": "create_file",
                "target_system": "filesystem",
                "payload_summary": "Creating test.py",
            },
            intent_id=intent["intent_id"],
        )
        artifact_id = eval_result["artifact_id"]

        # Verify the signature
        verification = sdk.verify_artifact(artifact_id)
        assert verification is not None
        assert verification["valid"] is True


class TestSDKHealth:
    def test_health_check(self, sdk):
        assert sdk.health() is True


class TestSDKTelemetry:
    def test_get_telemetry_stats(self, sdk):
        stats = sdk.get_telemetry_stats()
        assert stats is not None
        assert "total_decisions" in stats
