"""
End-to-end integration test -- Backend + SDK in one process.

Spins up the FastAPI backend via TestClient and injects it into the
SDK BackendClient. No mocks. Real SQLite DB, real Ed25519 signing,
real behavioral detectors.

Run:
  cd sdk/python
  python tests/test_e2e.py
"""

import os
import sys
import shutil
import tempfile

_HERE = os.path.abspath(os.path.dirname(__file__))
_SDK_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
_BACKEND_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", "..", "backend"))

sys.path.insert(0, _SDK_ROOT)
sys.path.insert(0, _BACKEND_ROOT)

_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(_tmp, "e2e.db").replace("\\", "/")
os.environ["AUDIT_STORAGE_DIR"] = os.path.join(_tmp, "audit")

from app.main import app  # noqa: E402
from app.database import init_db  # noqa: E402

init_db()

from fastapi.testclient import TestClient  # noqa: E402

_test_client = TestClient(app)

from scouter.client import ScouterClient  # noqa: E402
from scouter.models import ActionProposal, ActualExecution  # noqa: E402
from scouter.api.backend import BackendClient  # noqa: E402


def _make_backend_client() -> BackendClient:
    """Create a BackendClient backed by the in-process TestClient."""
    return BackendClient(
        base_url="http://localhost:8000",
        client=_test_client,
    )


def test_backend_health():
    r = _test_client.get("/health")
    assert r.status_code == 200
    print("  [+] backend health OK")


def test_full_sdk_with_backend():
    """Full flow: SDK -> Backend -> Ed25519 Signing -> Behavioral Analysis."""

    bc = _make_backend_client()

    # Inject the test-backed BackendClient into ScouterClient
    client = ScouterClient(api_key="e2e-test", mode="audit", verbose=False)
    client.backend = bc
    print("  [+] SDK connected to backend (injected)")

    # Register intent via backend
    result = bc.register_intent(
        agent_id="e2e-agent",
        natural_language="Create and write files in the workspace",
        permitted_actions=["create_file", "write_file", "read_file"],
        excluded_actions=["delete", "send:external"],
    )
    assert result is not None
    intent_id = result["intent_id"]
    assert intent_id
    print(f"  [+] Intent registered: {intent_id}")

    # Evaluate permitted action
    action = {
        "action_type": "create_file",
        "target_system": "filesystem",
        "payload_summary": '{"file_path":"test.py","content":"print()"}',
        "delegation_depth": 0,
    }
    decision = bc.evaluate(action, intent_id)
    assert decision is not None
    assert decision["evaluation"]["actual_execution"] == "AUDIT_PASS"
    assert decision["evaluation"]["calculated_decision"] == "PASS_THROUGH"
    assert decision["signature"]
    assert decision["public_key_id"]
    artifact_id = decision["artifact_id"]
    print(f"  [+] Permitted action -> PASS_THROUGH, artifact signed: {artifact_id[:12]}...")

    # Verify Ed25519 signature
    verify = bc.verify_artifact(artifact_id)
    assert verify is not None
    assert verify["valid"] is True
    print("  [+] Ed25519 signature verified")

    # Evaluate excluded action
    bad = bc.evaluate({
        "action_type": "delete:records",
        "target_system": "postgres",
        "payload_summary": "DROP TABLE users",
        "delegation_depth": 0,
    }, intent_id)
    assert bad is not None
    assert bad["evaluation"]["calculated_decision"] in ("HARD_STOP", "ESCALATE")
    assert bad["evaluation"]["actual_execution"] == "AUDIT_PASS"
    assert bad["signature"]
    print(f"  [+] Excluded action -> {bad['evaluation']['calculated_decision']}, signed")

    # Ingest trace spans
    trace_id = client.trace_id
    bc.ingest_span(trace_id, "request", {
        "messages": [{"role": "user", "content": "Create hello.py"}],
        "tools": ["create_file"],
    }, agent_id="e2e-agent", intent_id=intent_id)
    bc.ingest_span(trace_id, "response", {
        "content": None,
        "tool_calls": [{"name": "create_file", "arguments": "{}"}],
        "tools_available": True,
    }, agent_id="e2e-agent", intent_id=intent_id)
    bc.ingest_span(trace_id, "tool_call", {
        "tool_name": "create_file",
        "arguments": {"file_path": "hello.py", "content": "print('hi')"},
    })
    print(f"  [+] 3 trace spans ingested for {trace_id}")

    # Behavioral analysis (clean trace)
    analysis = bc.analyze_trace(trace_id)
    assert analysis is not None
    print(f"  [+] Behavioral analysis: {analysis['count']} findings")

    # Compliance export
    export = bc.export_compliance()
    assert export is not None
    assert export["total_artifacts"] >= 2
    assert export["public_key"]
    print(f"  [+] Compliance export: {export['total_artifacts']} artifacts")


def test_behavioral_detectors():
    """All 4 behavioral detectors through the backend."""

    bc = _make_backend_client()

    # Laziness
    bc.ingest_span("e2e-lazy", "request", {
        "messages": [{"role": "user", "content": "Create a file"}], "tools": ["create_file"],
    })
    bc.ingest_span("e2e-lazy", "response", {
        "content": "I'm not able to do that. Please check the dashboard yourself.",
        "tool_calls": [], "tools_available": True,
    })
    r = bc.analyze_trace("e2e-lazy")
    assert any(f["failure_type"] == "agent_laziness" for f in r["findings"])
    print(f"  [+] Laziness detected: confidence={r['findings'][0]['confidence']}")

    # Tool Misuse
    bc.ingest_span("e2e-misuse", "request", {
        "messages": [{"role": "user", "content": "Send the report"}],
    })
    bc.ingest_span("e2e-misuse", "response", {
        "content": "I have sent the email successfully.", "tool_calls": [], "tools_available": True,
    })
    r = bc.analyze_trace("e2e-misuse")
    assert any(f["failure_type"] == "tool_misuse" for f in r["findings"])
    print(f"  [+] Tool misuse detected")

    # User Frustration
    bc.ingest_span("e2e-frust", "request", {
        "messages": [
            {"role": "user", "content": "THIS IS BROKEN AND USELESS"},
            {"role": "user", "content": "TERRIBLE AWFUL NOT WORKING"},
        ],
    })
    bc.ingest_span("e2e-frust", "response", {
        "content": "I apologize.", "tool_calls": [],
    })
    r = bc.analyze_trace("e2e-frust")
    assert any(f["failure_type"] == "user_frustration" for f in r["findings"])
    print(f"  [+] User frustration detected")


def test_local_fallback():
    """SDK works without backend (local mode)."""
    client = ScouterClient(mode="audit", verbose=False)
    assert client.backend is None

    intent = client.registry.register(
        agent_id="local-agent", intent="Create files",
        permitted_actions=["create_file"], excluded_actions=["delete"],
    )
    action = ActionProposal(action_type="create_file", target_system="fs", payload_summary="test")
    decision = client.engine.evaluate(action, intent)
    assert decision.evaluation.actual_execution == ActualExecution.AUDIT_PASS
    print("  [+] Local fallback works")


def cleanup():
    shutil.rmtree(_tmp, ignore_errors=True)


if __name__ == "__main__":
    print("\n  Running end-to-end integration tests...\n")
    try:
        test_backend_health()
        test_full_sdk_with_backend()
        test_behavioral_detectors()
        test_local_fallback()
        print("\n  All E2E tests passed [+]\n")
    finally:
        cleanup()
