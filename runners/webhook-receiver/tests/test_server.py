"""End-to-end tests for the FastAPI receiver. Skipped when fastapi /
httpx are not available — they are an opt-in extra."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVER_PATH = REPO_ROOT / "runners" / "webhook-receiver" / "src" / "server.py"
spec = importlib.util.spec_from_file_location("webhook_server_test", SERVER_PATH)
assert spec and spec.loader


def _load_server(monkeypatch):
    """Reload the server module so test env vars take effect."""
    if "webhook_server_test" in sys.modules:
        del sys.modules["webhook_server_test"]
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _hex_hmac(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _signed(secret: str, body: bytes, ts: int | None = None) -> dict[str, str]:
    stamp = str(int(time.time()) if ts is None else ts)
    sig = _hex_hmac(secret, stamp.encode() + b"." + body)
    return {"X-Hub-Signature-256": f"sha256={sig}", "X-Webhook-Timestamp": stamp}


class _Done:
    returncode = 0
    stdout = b""
    stderr = b""


def _capture_audit(monkeypatch, server) -> list[dict]:
    events: list[dict] = []
    monkeypatch.setattr(server, "_emit_audit", events.append)
    return events


def test_healthz_returns_ok(monkeypatch):
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "webhook-receiver"}


UNAUTH_ROUTES = [
    "this-skill-does-not-exist",
    "ingest-cloudtrail-ocsf",
    "ingest-okta-system-log-ocsf",
    "remediate-mcp-tool-quarantine",
]


@pytest.mark.parametrize(
    "auth_env",
    [
        {},
        {"WEBHOOK_BEARER_TOKEN": "real"},
        {"WEBHOOK_HMAC_SECRETS": json.dumps({"ingest-cloudtrail-ocsf": "secret"})},
    ],
    ids=["no-auth-configured", "bearer-configured", "hmac-configured"],
)
def test_unauthenticated_requests_get_uniform_401_on_every_route(monkeypatch, auth_env):
    """Before auth, an unknown skill, a non-allowlisted skill, a wrong-category
    skill, and an allowlisted skill must be indistinguishable."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.delenv("WEBHOOK_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("WEBHOOK_HMAC_SECRETS", raising=False)
    for key, value in auth_env.items():
        monkeypatch.setenv(key, value)
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    responses = [client.post(f"/webhook/{route}", content=b"{}") for route in UNAUTH_ROUTES]
    assert {r.status_code for r in responses} == {401}
    assert {r.text for r in responses} == {'{"detail":"unauthorized"}'}


def test_unknown_skill_returns_404_after_auth(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "")
    monkeypatch.setenv("WEBHOOK_BEARER_TOKEN", "real")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post(
        "/webhook/this-skill-does-not-exist",
        content=b"{}",
        headers={"Authorization": "Bearer real"},
    )
    assert resp.status_code == 404


def test_known_skill_outside_allowlist_returns_403_after_auth(monkeypatch):
    """Default-deny — the skill ships but the operator has not opted it in."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "")
    monkeypatch.setenv("WEBHOOK_BEARER_TOKEN", "real")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf",
        content=b"{}",
        headers={"Authorization": "Bearer real"},
    )
    assert resp.status_code == 403


def test_remediation_skill_is_refused_even_if_allowlisted(monkeypatch):
    """Receiver refuses non-ingestion categories regardless of allowlist."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "remediate-mcp-tool-quarantine")
    monkeypatch.setenv("WEBHOOK_BEARER_TOKEN", "real")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post(
        "/webhook/remediate-mcp-tool-quarantine",
        content=b"{}",
        headers={"Authorization": "Bearer real"},
    )
    assert resp.status_code == 403
    assert "ingestion" in resp.json()["detail"]


def test_hmac_secret_on_non_allowlisted_skill_returns_403_after_auth(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "")
    monkeypatch.delenv("WEBHOOK_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("WEBHOOK_HMAC_SECRETS", json.dumps({"ingest-cloudtrail-ocsf": "secret"}))
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf", content=b"{}", headers=_signed("secret", b"{}")
    )
    assert resp.status_code == 403


def _hmac_server(monkeypatch, **extra_env):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.delenv("WEBHOOK_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("WEBHOOK_ALLOW_LEGACY_HMAC", raising=False)
    monkeypatch.setenv("WEBHOOK_HMAC_SECRETS", json.dumps({"ingest-cloudtrail-ocsf": "secret"}))
    monkeypatch.setenv("WEBHOOK_SINK_TARGETS", "")
    for key, value in extra_env.items():
        monkeypatch.setenv(key, value)
    server = _load_server(monkeypatch)
    monkeypatch.setattr(server.subprocess, "run", lambda *a, **k: _Done())
    return server


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({}, "missing_signature"),
        (
            {"X-Hub-Signature-256": "sha256=" + "0" * 64, "X-Webhook-Timestamp": "1"},
            "signature_invalid",
        ),
        ({"X-Hub-Signature-256": "sha256=" + _hex_hmac("secret", b"{}")}, "missing_timestamp"),
    ],
)
def test_hmac_failures_return_uniform_401_with_reason_in_audit(monkeypatch, headers, reason):
    server = _hmac_server(monkeypatch)
    events = _capture_audit(monkeypatch, server)
    client = TestClient(server.app)
    resp = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}", headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "unauthorized"
    assert events[-1]["error_type"] == reason


def test_stale_timestamp_returns_401(monkeypatch):
    server = _hmac_server(monkeypatch)
    events = _capture_audit(monkeypatch, server)
    client = TestClient(server.app)
    stale = int(time.time()) - 301
    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf", content=b"{}", headers=_signed("secret", b"{}", stale)
    )
    assert resp.status_code == 401
    assert events[-1]["error_type"] == "timestamp_out_of_window"


def test_replayed_signed_request_is_rejected(monkeypatch):
    server = _hmac_server(monkeypatch)
    events = _capture_audit(monkeypatch, server)
    client = TestClient(server.app)
    headers = _signed("secret", b"{}")
    first = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}", headers=headers)
    second = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}", headers=headers)
    assert first.status_code == 200, first.text
    assert second.status_code == 401
    assert events[-1]["error_type"] == "replayed_request"
    # A fresh signature for the same body is a new delivery and is accepted.
    third = client.post(
        "/webhook/ingest-cloudtrail-ocsf",
        content=b"{}",
        headers=_signed("secret", b"{}", int(time.time()) - 1),
    )
    assert third.status_code == 200, third.text


def test_legacy_body_only_hmac_requires_opt_in(monkeypatch):
    legacy = {"X-Hub-Signature-256": "sha256=" + _hex_hmac("secret", b"{}")}
    server = _hmac_server(monkeypatch)
    client = TestClient(server.app)
    assert (
        client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}", headers=legacy).status_code
        == 401
    )

    server = _hmac_server(monkeypatch, WEBHOOK_ALLOW_LEGACY_HMAC="1")
    events = _capture_audit(monkeypatch, server)
    client = TestClient(server.app)
    first = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}", headers=legacy)
    assert first.status_code == 200, first.text
    assert events[-1]["hmac_scheme"] == "legacy_body_only"
    replay = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}", headers=legacy)
    assert replay.status_code == 401


def test_bearer_required_when_configured(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.setenv("WEBHOOK_BEARER_TOKEN", "real")
    server = _load_server(monkeypatch)
    events = _capture_audit(monkeypatch, server)
    client = TestClient(server.app)
    resp = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "unauthorized"
    assert events[-1]["error_type"] == "missing_bearer"


def test_invalid_tolerance_refuses_to_start(monkeypatch):
    monkeypatch.setenv("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", "0")
    with pytest.raises(ValueError, match="WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS"):
        _load_server(monkeypatch)


def test_valid_signature_routes_to_skill(monkeypatch, tmp_path):
    """Smoke test the happy path: POST a CloudTrail-shape payload, confirm
    the receiver invokes the skill, captures stdout, and returns a 200
    with the skill_exit_code surfaced."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.setenv(
        "WEBHOOK_HMAC_SECRETS",
        json.dumps({"ingest-cloudtrail-ocsf": "secret"}),
    )
    monkeypatch.setenv("WEBHOOK_SINK_TARGETS", "")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)

    body = (
        REPO_ROOT / "skills" / "detection-engineering" / "golden" / "cloudtrail_raw_sample.jsonl"
    ).read_bytes()
    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf",
        content=body,
        headers={**_signed("secret", body), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["skill"] == "ingest-cloudtrail-ocsf"
    assert payload["skill_exit_code"] == 0
    assert payload["stdout_length"] > 0
    assert payload["sink_results"] == []  # no sinks configured


def _cloudtrail_body() -> bytes:
    return (
        REPO_ROOT / "skills" / "detection-engineering" / "golden" / "cloudtrail_raw_sample.jsonl"
    ).read_bytes()


def test_no_auth_configured_fails_closed(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.delenv("WEBHOOK_HMAC_SECRETS", raising=False)
    monkeypatch.delenv("WEBHOOK_BEARER_TOKEN", raising=False)
    server = _load_server(monkeypatch)

    def _boom(*args, **kwargs):
        raise AssertionError("skill must not run without auth")

    monkeypatch.setattr(server.subprocess, "run", _boom)
    events = _capture_audit(monkeypatch, server)
    client = TestClient(server.app)
    resp = client.post("/webhook/ingest-cloudtrail-ocsf", content=_cloudtrail_body())
    assert resp.status_code == 401
    assert resp.json()["detail"] == "unauthorized"
    assert events[-1]["error_type"] == "auth_not_configured"


def test_malformed_hmac_secrets_refuse_to_start(monkeypatch):
    monkeypatch.setenv("WEBHOOK_HMAC_SECRETS", "{not json")
    with pytest.raises(ValueError, match="WEBHOOK_HMAC_SECRETS"):
        _load_server(monkeypatch)


def test_invalid_max_body_refuses_to_start(monkeypatch):
    monkeypatch.setenv("WEBHOOK_MAX_BODY_BYTES", "-5")
    with pytest.raises(ValueError, match="WEBHOOK_MAX_BODY_BYTES"):
        _load_server(monkeypatch)


def test_oversized_body_returns_413(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.setenv("WEBHOOK_BEARER_TOKEN", "real")
    monkeypatch.setenv("WEBHOOK_MAX_BODY_BYTES", "64")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf",
        content=b"x" * 65,
        headers={"Authorization": "Bearer real"},
    )
    assert resp.status_code == 413

    def _chunks():
        yield b"x" * 40
        yield b"x" * 40

    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf",
        content=_chunks(),
        headers={"Authorization": "Bearer real"},
    )
    assert resp.status_code == 413


def test_default_body_cap_is_one_mib(monkeypatch):
    monkeypatch.delenv("WEBHOOK_MAX_BODY_BYTES", raising=False)
    server = _load_server(monkeypatch)
    assert server.MAX_BODY_BYTES == 1024 * 1024


def test_skill_env_excludes_wrapper_secrets(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.setenv("WEBHOOK_BEARER_TOKEN", "real")
    monkeypatch.setenv("WEBHOOK_SINK_TARGETS", "")
    monkeypatch.setenv("CLOUD_SECURITY_AUDIT_HMAC_KEY", "k" * 40)
    monkeypatch.setenv("CLOUD_SECURITY_MCP_AUDIT_LOG", "/dev/null")
    monkeypatch.setenv("CLOUD_SECURITY_HTTP_MAX_ATTEMPTS", "3")
    server = _load_server(monkeypatch)
    captured: dict[str, dict[str, str]] = {}

    class _Done:
        returncode = 0
        stdout = b""
        stderr = b""

    def _fake_run(*args, **kwargs):
        captured["env"] = kwargs["env"]
        return _Done()

    monkeypatch.setattr(server.subprocess, "run", _fake_run)
    client = TestClient(server.app)
    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf",
        content=_cloudtrail_body(),
        headers={"Authorization": "Bearer real"},
    )
    assert resp.status_code == 200, resp.text
    env = captured["env"]
    assert "CLOUD_SECURITY_AUDIT_HMAC_KEY" not in env
    assert "CLOUD_SECURITY_MCP_AUDIT_LOG" not in env
    assert env["CLOUD_SECURITY_HTTP_MAX_ATTEMPTS"] == "3"
