"""The one-shot subprocess path enforces the worker pool's stdout/stderr cap."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

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


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group cleanup")
@pytest.mark.parametrize("parent_exits", [True, False])
def test_deadline_covers_descendants_holding_pipes(parent_exits):
    # A finite sleeper keeps a broken implementation from hanging this test forever.
    code = (
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)'])\n"
        + ("" if parent_exits else "time.sleep(2)\n")
    )
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _run(code, timeout=0.3)
    assert time.monotonic() - started < 1.5


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("threaded", [False, True])
def test_small_overflow_is_detected_before_child_exits(monkeypatch, stream, threaded):
    if threaded:
        # Exercise fallback pipe I/O without claiming Windows process-tree coverage.
        monkeypatch.setattr(MODULE, "os", SimpleNamespace(name="nt"))
    monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_MAX_BYTES", "1024")
    started = time.monotonic()
    completed = _run(
        f"import os, time; os.write({1 if stream == 'stdout' else 2}, b'x' * 1025); time.sleep(2)",
        timeout=3,
    )
    assert completed.returncode == 1
    assert "CLOUD_SECURITY_MCP_WORKER_MAX_BYTES" in completed.stderr
    assert time.monotonic() - started < 1.5


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("threaded", [False, True])
def test_invalid_output_encoding_cannot_be_reported_as_success(monkeypatch, stream, threaded):
    if threaded:
        # Exercise fallback pipe I/O without claiming Windows process-tree coverage.
        monkeypatch.setattr(MODULE, "os", SimpleNamespace(name="nt"))
    with pytest.raises(RuntimeError, match="skill output could not be decoded as text"):
        _run(f"import os; os.write({1 if stream == 'stdout' else 2}, b'\\xff')")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group cleanup")
def test_closed_pipes_do_not_skip_process_deadline():
    with pytest.raises(subprocess.TimeoutExpired):
        _run("import os, time; os.close(1); os.close(2); time.sleep(2)", timeout=0.3)


def test_early_stdin_close_still_collects_output():
    completed = _run("import os; os.close(0); print('done')", stdin_text="x" * (4 * 1024 * 1024))
    assert completed.returncode == 0
    assert completed.stdout == "done\n"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("threaded", [False, True])
def test_cap_counts_raw_bytes_before_newline_translation(monkeypatch, stream, threaded):
    if threaded:
        # Exercise fallback pipe I/O without claiming Windows process-tree coverage.
        monkeypatch.setattr(MODULE, "os", SimpleNamespace(name="nt"))
    monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_MAX_BYTES", "1024")
    completed = _run(f"import os; os.write({1 if stream == 'stdout' else 2}, b'\\r\\n' * 513)")
    assert completed.returncode == 1
    assert completed.stdout == ""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group cleanup")
@pytest.mark.parametrize("ending", ["success", "timeout", "overflow"])
def test_owned_descendants_are_stopped_without_killing_sibling(tmp_path, ending):
    ready = tmp_path / "ready"
    escaped = tmp_path / "escaped"
    descendant = (
        "from pathlib import Path; import time; "
        f"Path({str(ready)!r}).touch(); time.sleep(1); Path({str(escaped)!r}).touch()"
    )
    code = (
        "import subprocess, sys, time\nfrom pathlib import Path\n"
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        f"while not Path({str(ready)!r}).exists(): time.sleep(0.01)\n"
        + {
            "success": "print('done')\n",
            "timeout": "time.sleep(2)\n",
            "overflow": f"sys.stdout.write('x' * {CAP + 1}); sys.stdout.flush(); time.sleep(2)\n",
        }[ending]
    )
    # This sibling is in our group, outside the invocation's new session.
    with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"]) as sibling:
        try:
            if ending == "timeout":
                with pytest.raises(subprocess.TimeoutExpired):
                    _run(code, timeout=0.5)
            else:
                completed = _run(code, timeout=2)
                assert completed.returncode == (0 if ending == "success" else 1)
            assert ready.exists()
            assert sibling.poll() is None
            time.sleep(1.1)
            assert not escaped.exists()
        finally:
            sibling.kill()
            sibling.wait()


@pytest.mark.parametrize("failure", ["timeout", "encoding"])
def test_failed_process_is_audited_and_next_request_succeeds(monkeypatch, failure):
    monkeypatch.setattr(MODULE, "tool_map", lambda: {"fake-skill": _FakeSkill()})
    monkeypatch.setattr(MODULE, "_resolve_timeout", lambda skill, env: 1)
    code = (
        "import time; time.sleep(2)" if failure == "timeout" else "import os; os.write(1, b'\\xff')"
    )
    monkeypatch.setattr(
        MODULE, "build_command", lambda *args, **kwargs: [sys.executable, "-c", code]
    )
    audit_events = []
    monkeypatch.setattr(MODULE, "_emit_audit_event", audit_events.append)
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "fake-skill", "arguments": {}},
    }
    response = MODULE._handle_request(request)
    expected_code = MODULE.ERROR_TOOL_TIMEOUT if failure == "timeout" else MODULE.ERROR_TOOL_CRASHED
    assert response["error"]["code"] == expected_code
    assert len(audit_events) == 1
    assert audit_events[0]["result"] == "error"
    assert audit_events[0]["error_type"] == (
        "TimeoutExpired" if failure == "timeout" else "RuntimeError"
    )
    if failure == "encoding":
        assert (
            response["error"]["message"]
            == "tool crashed: RuntimeError: skill output could not be decoded as text"
        )
        assert audit_events[0]["error_message"] == "skill output could not be decoded as text"

    code = "print('recovered')"
    response = MODULE._handle_request({**request, "id": 2})
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["stdout"] == "recovered\n"
    assert len(audit_events) == 2
    assert audit_events[1]["result"] == "success"
