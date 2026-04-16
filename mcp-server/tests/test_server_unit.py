from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"
SPEC = importlib.util.spec_from_file_location("cloud_security_server_test", SERVER_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class _FakeCompleted:
    def __init__(self) -> None:
        self.stdout = "ok\n"
        self.stderr = ""
        self.returncode = 0


class _FakeSkill:
    def __init__(
        self,
        read_only: bool = True,
        approver_roles: tuple[str, ...] = (),
        mcp_timeout_seconds: int | None = None,
    ) -> None:
        self.name = "fake-skill"
        self.category = "detection"
        self.capability = "read-only" if read_only else "write-remediation"
        self.read_only = read_only
        self.approver_roles = approver_roles
        self.mcp_timeout_seconds = mcp_timeout_seconds


def test_call_tool_injects_caller_and_approval_context(monkeypatch):
    captured: dict[str, object] = {}
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(MODULE, "tool_map", lambda: {"fake-skill": _FakeSkill(read_only=True)})
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    def _fake_run(*args, **kwargs):
        captured["env"] = kwargs["env"]
        return _FakeCompleted()

    monkeypatch.setattr(MODULE.subprocess, "run", _fake_run)

    result = MODULE._call_tool(
        "fake-skill",
        {
            "args": [],
            "_caller_context": {
                "user_id": "u-123",
                "email": "user@example.com",
                "session_id": "sess-1",
                "roles": ["security_engineer"],
            },
            "_approval_context": {
                "approver_id": "a-456",
                "approver_email": "approver@example.com",
                "ticket_id": "SEC-123",
                "approval_timestamp": "2026-04-14T12:00:00Z",
            },
        },
    )

    env = captured["env"]
    assert env["SKILL_CALLER_ID"] == "u-123"
    assert env["SKILL_CALLER_EMAIL"] == "user@example.com"
    assert env["SKILL_SESSION_ID"] == "sess-1"
    assert env["SKILL_CALLER_ROLES"] == "security_engineer"
    assert env["SKILL_APPROVER_ID"] == "a-456"
    assert env["SKILL_APPROVER_EMAIL"] == "approver@example.com"
    assert env["SKILL_APPROVAL_TICKET"] == "SEC-123"
    assert env["SKILL_APPROVAL_TIMESTAMP"] == "2026-04-14T12:00:00Z"
    assert result["structuredContent"]["caller_context_provided"] is True
    assert result["structuredContent"]["approval_context_provided"] is True
    assert audit_events[0]["tool"] == "fake-skill"
    assert audit_events[0]["result"] == "success"
    assert audit_events[0]["caller_id"] == "u-123"
    assert audit_events[0]["approval_ticket"] == "SEC-123"
    assert audit_events[0]["args_count"] == 0
    assert audit_events[0]["input_length"] == 0


def test_call_tool_requires_approval_context_for_write_skill(monkeypatch):
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(
        MODULE,
        "tool_map",
        lambda: {"fake-skill": _FakeSkill(read_only=False, approver_roles=("security_lead",))},
    )
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    try:
        MODULE._call_tool("fake-skill", {"args": ["--dry-run"]})
    except ValueError as exc:
        assert "require `_approval_context`" in str(exc)
    else:
        raise AssertionError("expected ValueError")
    assert audit_events[0]["tool"] == "fake-skill"
    assert audit_events[0]["result"] == "error"
    assert audit_events[0]["error_type"] == "ValueError"
    assert audit_events[0]["args_hash"] == MODULE._stable_hash(["--dry-run"])
    assert audit_events[0]["approval_context_provided"] is False


def test_resolve_timeout_prefers_env_override():
    skill = _FakeSkill(mcp_timeout_seconds=45)
    env = {"CLOUD_SECURITY_MCP_TIMEOUT_SECONDS": "300"}
    assert MODULE._resolve_timeout(skill, env) == 300


def test_resolve_timeout_uses_skill_value_when_no_env_override():
    skill = _FakeSkill(mcp_timeout_seconds=120)
    env: dict[str, str] = {}
    assert MODULE._resolve_timeout(skill, env) == 120


def test_resolve_timeout_falls_back_to_default_when_neither_set():
    skill = _FakeSkill(mcp_timeout_seconds=None)
    env: dict[str, str] = {}
    assert MODULE._resolve_timeout(skill, env) == MODULE.DEFAULT_TIMEOUT_SECONDS


def test_resolve_timeout_ignores_blank_env_override():
    skill = _FakeSkill(mcp_timeout_seconds=90)
    env = {"CLOUD_SECURITY_MCP_TIMEOUT_SECONDS": "   "}
    assert MODULE._resolve_timeout(skill, env) == 90


def test_call_tool_audit_records_resolved_timeout(monkeypatch):
    audit_events: list[dict[str, object]] = []
    monkeypatch.setattr(
        MODULE,
        "tool_map",
        lambda: {"fake-skill": _FakeSkill(mcp_timeout_seconds=150)},
    )
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    def _fake_run(*args, **kwargs):
        assert kwargs["timeout"] == 150
        return _FakeCompleted()

    monkeypatch.setattr(MODULE.subprocess, "run", _fake_run)
    monkeypatch.delenv("CLOUD_SECURITY_MCP_TIMEOUT_SECONDS", raising=False)
    MODULE._call_tool("fake-skill", {"args": []})
    assert audit_events[0]["timeout_seconds"] == 150
