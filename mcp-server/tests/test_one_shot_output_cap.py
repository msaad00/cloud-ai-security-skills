"""The one-shot subprocess path enforces the worker pool's stdout/stderr cap."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"
SPEC = importlib.util.spec_from_file_location("cloud_security_server_cap_test", SERVER_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CAP = 64 * 1024
FLOOD = "import sys\nwhile True:\n    sys.{stream}.write('x' * 65536)\n    sys.{stream}.flush()\n"


@pytest.fixture(autouse=True)
def _small_cap(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_MAX_BYTES", str(CAP))


def _run(code: str, stdin_text: str = "", timeout: float = 30) -> subprocess.CompletedProcess:
    return MODULE._run_one_shot(
        [sys.executable, "-c", code],
        stdin_text=stdin_text,
        cwd=str(REPO_ROOT),
        env=None,
        timeout=timeout,
        preexec_fn=None,
    )


def test_matches_subprocess_run_within_cap():
    code = (
        "import sys\n"
        "data = sys.stdin.read()\n"
        "sys.stdout.write(data.upper() + 'line\\r\\n')\n"
        "sys.stderr.write('warn\\n')\n"
        "sys.exit(3)\n"
    )
    stdin_text = "alpha\nbeta é\n" * 1000
    expected = subprocess.run(
        [sys.executable, "-c", code],
        input=stdin_text,
        text=True,
        capture_output=True,
        cwd=str(REPO_ROOT),
        check=False,
    )
    completed = _run(code, stdin_text)
    assert (completed.returncode, completed.stdout, completed.stderr) == (
        expected.returncode,
        expected.stdout,
        expected.stderr,
    )


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_kills_child_that_exceeds_cap(stream):
    started = time.monotonic()
    completed = _run(FLOOD.format(stream=stream))
    assert time.monotonic() - started < 20
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "CLOUD_SECURITY_MCP_WORKER_MAX_BYTES" in completed.stderr
    assert str(CAP) in completed.stderr


def test_output_exactly_at_cap_is_kept():
    completed = _run(f"import sys; sys.stdout.write('y' * {CAP})")
    assert completed.returncode == 0
    assert completed.stdout == "y" * CAP


def test_timeout_raises_timeout_expired():
    with pytest.raises(subprocess.TimeoutExpired):
        _run("import time; time.sleep(30)", timeout=1)


def test_timeout_enforced_when_child_ignores_large_stdin():
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _run("import time; time.sleep(30)", stdin_text="z" * (4 * 1024 * 1024), timeout=1)
    assert time.monotonic() - started < 20


class _FakeSkill:
    name = "fake-skill"
    category = "detection"
    capability = "read-only"
    read_only = True
    approver_roles: tuple[str, ...] = ()
    min_approvers = None
    mcp_timeout_seconds = 30
    entrypoint = None
    skill_dir = Path("/nonexistent/fake-skill")


def test_call_tool_returns_error_instead_of_unbounded_output(monkeypatch):
    monkeypatch.setattr(MODULE, "tool_map", lambda: {"fake-skill": _FakeSkill()})
    monkeypatch.setattr(
        MODULE,
        "build_command",
        lambda skill, args, output_format=None: [
            sys.executable,
            "-c",
            FLOOD.format(stream="stdout"),
        ],
    )
    audit_events: list[dict[str, object]] = []
    monkeypatch.setattr(MODULE, "_emit_audit_event", audit_events.append)

    result = MODULE._call_tool("fake-skill", {"args": []})

    assert result["isError"] is True
    assert result["structuredContent"]["stdout"] == ""
    assert result["structuredContent"]["exit_code"] == 1
    assert "CLOUD_SECURITY_MCP_WORKER_MAX_BYTES" in result["content"][0]["text"]
    assert audit_events[0]["result"] == "error"
