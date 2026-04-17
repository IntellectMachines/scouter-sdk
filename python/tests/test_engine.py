"""
Unit tests for the Scouter core engine and file-operation tools.
"""

import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scouter.client import ScouterClient
from scouter.models import ActionProposal, Decision, ActualExecution
from scouter.tools import file_ops


def test_intent_registration() -> None:
    client = ScouterClient(mode="audit", verbose=False)
    intent = client.registry.register(
        agent_id="file-ops-agent",
        intent="Create and write files in the workspace",
        permitted_actions=["create_file", "write_file", "read_file"],
        excluded_actions=["delete", "send:external"],
    )
    assert intent.intent_id
    assert intent.agent_id == "file-ops-agent"
    assert "create_file" in intent.permitted_actions
    assert "delete" in intent.excluded_actions
    print("  ✓ test_intent_registration passed")


def test_consequence_engine_permitted_action() -> None:
    """A permitted tool call (create_file) → PASS_THROUGH."""
    client = ScouterClient(mode="audit", verbose=False)
    intent = client.registry.register(
        agent_id="file-ops-agent",
        intent="Create and write files in the workspace",
        permitted_actions=["create_file", "write_file", "read_file"],
    )
    action = ActionProposal(
        action_type="create_file",
        target_system="openai-tool-call",
        payload_summary='{"file_path": "hello.py", "content": "print(\'hello\')"}',
    )
    decision = client.engine.evaluate(action, intent)
    assert decision.evaluation.calculated_decision == Decision.PASS_THROUGH
    assert decision.evaluation.actual_execution == ActualExecution.AUDIT_PASS
    print("  ✓ test_consequence_engine_permitted_action passed")


def test_consequence_engine_excluded_action() -> None:
    """An excluded action (delete) → HARD_STOP or ESCALATE."""
    client = ScouterClient(mode="audit", verbose=False)
    intent = client.registry.register(
        agent_id="file-ops-agent",
        intent="Create and write files",
        permitted_actions=["create_file", "write_file"],
        excluded_actions=["delete", "send:external"],
    )
    action = ActionProposal(
        action_type="delete:records",
        target_system="filesystem",
        payload_summary="rm -rf /workspace",
    )
    decision = client.engine.evaluate(action, intent)
    assert decision.evaluation.calculated_decision in (
        Decision.HARD_STOP,
        Decision.ESCALATE,
        Decision.FLAG,
    )
    assert decision.evaluation.actual_execution == ActualExecution.AUDIT_PASS
    print("  ✓ test_consequence_engine_excluded_action passed")


def test_governance_decision_fields() -> None:
    """Verify all STD §5.2 fields are populated on the artifact."""
    client = ScouterClient(mode="audit", verbose=False)
    action = ActionProposal(
        action_type="write_file",
        target_system="openai-tool-call",
        payload_summary='{"file_path": "test.txt", "content": "data"}',
    )
    decision = client.engine.evaluate(action)
    assert decision.artifact_id
    assert decision.timestamp
    assert decision.evaluation.irreversibility_score >= 0.0
    assert decision.evaluation.alignment_score >= 0.0
    assert decision.evaluation.rationale
    print("  ✓ test_governance_decision_fields passed")


def test_create_file_tool() -> None:
    """Real file creation on disk."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        result = file_ops.create_file("test.txt", "hello world")
        assert result.startswith("OK:")
        assert os.path.exists(os.path.join(tmp, "test.txt"))
        with open(os.path.join(tmp, "test.txt"), encoding="utf-8") as f:
            assert f.read() == "hello world"
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_create_file_tool passed")


def test_write_file_tool_overwrite() -> None:
    """Real file overwrite on disk."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        file_ops.create_file("data.txt", "original")
        result = file_ops.write_file("data.txt", "replaced", mode="overwrite")
        assert result.startswith("OK:")
        with open(os.path.join(tmp, "data.txt"), encoding="utf-8") as f:
            assert f.read() == "replaced"
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_write_file_tool_overwrite passed")


def test_write_file_tool_append() -> None:
    """Real file append on disk."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        file_ops.create_file("log.txt", "line1\n")
        result = file_ops.write_file("log.txt", "line2\n", mode="append")
        assert result.startswith("OK:")
        with open(os.path.join(tmp, "log.txt"), encoding="utf-8") as f:
            assert f.read() == "line1\nline2\n"
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_write_file_tool_append passed")


def test_read_file_tool() -> None:
    """Real file read from disk."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        file_ops.create_file("read_me.txt", "contents here")
        result = file_ops.read_file("read_me.txt")
        assert result == "contents here"
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_read_file_tool passed")


def test_create_file_nested_dirs() -> None:
    """Real creation of a file in nested directories."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        result = file_ops.create_file("config/sub/settings.json", '{"key": "value"}')
        assert result.startswith("OK:")
        assert os.path.exists(os.path.join(tmp, "config", "sub", "settings.json"))
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_create_file_nested_dirs passed")


def test_create_file_already_exists() -> None:
    """create_file should fail if file already exists."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        file_ops.create_file("dup.txt", "first")
        result = file_ops.create_file("dup.txt", "second")
        assert result.startswith("ERROR:")
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_create_file_already_exists passed")


def test_read_file_not_found() -> None:
    """read_file should return error for missing files."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        result = file_ops.read_file("missing.txt")
        assert result.startswith("ERROR:")
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_read_file_not_found passed")


def test_path_escape_blocked() -> None:
    """Attempting to escape the sandbox should raise PermissionError."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        result = file_ops.execute_tool("create_file", {
            "file_path": "../../etc/passwd",
            "content": "hacked",
        })
        assert "ERROR" in result
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_path_escape_blocked passed")


def test_execute_tool_dispatcher() -> None:
    """execute_tool routes to the correct function."""
    tmp = tempfile.mkdtemp()
    original_sandbox = file_ops.SANDBOX_DIR
    file_ops.SANDBOX_DIR = tmp
    try:
        result = file_ops.execute_tool("create_file", {
            "file_path": "dispatch_test.txt",
            "content": "dispatched",
        })
        assert result.startswith("OK:")
        result2 = file_ops.execute_tool("read_file", {"file_path": "dispatch_test.txt"})
        assert result2 == "dispatched"
    finally:
        file_ops.SANDBOX_DIR = original_sandbox
        shutil.rmtree(tmp)
    print("  ✓ test_execute_tool_dispatcher passed")


if __name__ == "__main__":
    print("\n  Running Scouter tests…\n")
    test_intent_registration()
    test_consequence_engine_permitted_action()
    test_consequence_engine_excluded_action()
    test_governance_decision_fields()
    test_create_file_tool()
    test_write_file_tool_overwrite()
    test_write_file_tool_append()
    test_read_file_tool()
    test_create_file_nested_dirs()
    test_create_file_already_exists()
    test_read_file_not_found()
    test_path_escape_blocked()
    test_execute_tool_dispatcher()
    print("\n  All tests passed ✓\n")
