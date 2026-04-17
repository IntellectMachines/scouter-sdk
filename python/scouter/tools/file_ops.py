"""
File operation tools — real implementations for the AI agent.

These are the actual callable tools that the OpenAI function-calling
agent will invoke. Each function performs a real filesystem operation
and returns a result string that gets fed back into the conversation.

Execution guards are applied automatically to dangerous operations.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from scouter.guards import ShellGuard, GuardDecision
from scouter.guards.execution_interceptor import ExecutionInterceptor


# Sandbox directory where the agent is allowed to operate
SANDBOX_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "agent_workspace")

# ── Global execution guard ─────────────────────────────────────────────
_interceptor = ExecutionInterceptor(mode="enforce", verbose=True)


def _resolve_path(file_path: str) -> Path:
    """Resolve a relative path inside the sandbox and ensure safety."""
    sandbox = Path(SANDBOX_DIR).resolve()
    target = (sandbox / file_path).resolve()
    if not str(target).startswith(str(sandbox)):
        raise PermissionError(f"Path escapes sandbox: {file_path}")
    return target


def create_file(file_path: str, content: str) -> str:
    """Create a new file with the given content. Parent dirs are created automatically."""
    target = _resolve_path(file_path)
    if target.exists():
        return f"ERROR: File already exists at '{file_path}'. Use write_file to overwrite."
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"OK: Created '{file_path}' ({len(content)} bytes)"


def write_file(file_path: str, content: str, mode: str = "overwrite") -> str:
    """Write content to a file. Mode can be 'overwrite' or 'append'."""
    target = _resolve_path(file_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if mode == "append":
        with open(target, "a", encoding="utf-8") as f:
            f.write(content)
        return f"OK: Appended {len(content)} bytes to '{file_path}'"
    else:
        target.write_text(content, encoding="utf-8")
        return f"OK: Wrote {len(content)} bytes to '{file_path}'"


def read_file(file_path: str) -> str:
    """Read and return the contents of a file."""
    target = _resolve_path(file_path)
    if not target.exists():
        return f"ERROR: File not found: '{file_path}'"
    return target.read_text(encoding="utf-8")


def delete_file(file_path: str) -> str:
    """Delete a file inside the sandbox (guarded)."""
    target = _resolve_path(file_path)
    if not target.exists():
        return f"ERROR: File not found: '{file_path}'"

    # Guard check — the shell guard catches dangerous patterns like 'rm -rf /'
    result = _interceptor.check_shell(f"rm {target}")
    if result.decision == GuardDecision.BLOCK:
        return f"BLOCKED by ShellGuard: {result.message}"

    target.unlink()
    return f"OK: Deleted '{file_path}'"


def run_shell_command(command: str, timeout: int = 30) -> str:
    """
    Run a shell command inside the sandbox directory (guarded).
    The ExecutionInterceptor checks the command BEFORE it runs.
    """
    # ── Guard gate ──
    result = _interceptor.check_shell(command)
    if result.decision == GuardDecision.BLOCK:
        return f"BLOCKED by ShellGuard: {result.message}"

    sandbox = Path(SANDBOX_DIR).resolve()
    sandbox.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(sandbox),
        )
        output = proc.stdout
        if proc.stderr:
            output += f"\nSTDERR:\n{proc.stderr}"
        if proc.returncode != 0:
            output += f"\n(exit code: {proc.returncode})"
        return output[:4000] if output else "(no output)"
    except subprocess.TimeoutExpired:
        return f"ERROR: Command timed out after {timeout}s"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


# ── OpenAI tool definitions ───────────────────────────────────────────

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "create_file",
            "description": "Create a new file at the given path with the provided content. Parent directories are created automatically. Fails if the file already exists.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path for the new file (e.g. 'reports/q1.md')",
                    },
                    "content": {
                        "type": "string",
                        "description": "The full text content to write into the file",
                    },
                },
                "required": ["file_path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write or append content to a file. Use mode='overwrite' to replace contents or mode='append' to add to the end.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to the file",
                    },
                    "content": {
                        "type": "string",
                        "description": "The text content to write",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["overwrite", "append"],
                        "description": "Write mode: 'overwrite' (default) or 'append'",
                    },
                },
                "required": ["file_path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read and return the full contents of a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to the file to read",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_file",
            "description": "Delete a file at the given path. Guarded by Scouter's ShellGuard.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to the file to delete",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": "Run a shell command in the agent workspace. Protected by Scouter's execution guards — dangerous commands are automatically blocked.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Max seconds to wait (default 30)",
                    },
                },
                "required": ["command"],
            },
        },
    },
]

# ── Dispatcher ────────────────────────────────────────────────────────

TOOL_FUNCTIONS = {
    "create_file": create_file,
    "write_file": write_file,
    "read_file": read_file,
    "delete_file": delete_file,
    "run_shell_command": run_shell_command,
}


def execute_tool(name: str, arguments: dict) -> str:
    """Dispatch a tool call by name. Returns the result string."""
    fn = TOOL_FUNCTIONS.get(name)
    if fn is None:
        return f"ERROR: Unknown tool '{name}'"
    try:
        return fn(**arguments)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"
