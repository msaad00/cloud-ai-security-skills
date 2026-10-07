"""Tests for `runners/webhook-receiver/src/auth.py`."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = REPO_ROOT / "runners" / "webhook-receiver" / "src" / "auth.py"
spec = importlib.util.spec_from_file_location("webhook_auth_test", SRC)
assert spec and spec.loader
AUTH = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = AUTH
spec.loader.exec_module(AUTH)


NOW = 1_800_000_000


def _hex_hmac(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _signed_headers(
    secret: str, body: bytes, ts: int = NOW, sig_header: str = "x-hub-signature-256"
) -> dict[str, str]:
    sig = _hex_hmac(secret, f"{ts}.".encode() + body)
    return {sig_header: f"sha256={sig}", "x-webhook-timestamp": str(ts)}


def _env(**extra: str) -> dict[str, str]:
    return {"WEBHOOK_HMAC_SECRETS": json.dumps({"ingest-x": "secret"}), **extra}


def test_hmac_passes_with_no_secret_configured():
    result = AUTH.verify_hmac("any-skill", {}, b"body", env={})
    assert result.ok is True


def test_hmac_rejects_when_secret_set_but_no_header():
    result = AUTH.verify_hmac("ingest-x", {}, b"body", env=_env(), now=NOW)
    assert result.ok is False
    assert result.reason == "missing_signature"


def test_hmac_rejects_invalid_signature():
    headers = {"x-hub-signature-256": "sha256=" + ("0" * 64), "x-webhook-timestamp": str(NOW)}
    result = AUTH.verify_hmac("ingest-x", headers, b"body", env=_env(), now=NOW)
    assert result.ok is False
    assert result.reason == "signature_invalid"


def test_hmac_accepts_timestamped_sha256_prefix_signature():
    body = b'{"evt": 1}'
    result = AUTH.verify_hmac(
        "ingest-x", _signed_headers("secret", body), body, env=_env(), now=NOW
    )
    assert result.ok is True
    assert result.replay_key
    assert result.replay_expires_at == NOW + 300


def test_hmac_accepts_timestamped_bare_hex_signature():
    body = b'{"evt": 1}'
    headers = _signed_headers("secret", body)
    headers["x-hub-signature-256"] = headers["x-hub-signature-256"].removeprefix("sha256=")
    assert AUTH.verify_hmac("ingest-x", headers, body, env=_env(), now=NOW).ok is True


def test_hmac_custom_header_name():
    env = _env(WEBHOOK_HMAC_HEADER="X-Vendor-Sig")
    body = b'{"evt": 1}'
    headers = _signed_headers("secret", body, sig_header="x-vendor-sig")
    assert AUTH.verify_hmac("ingest-x", headers, body, env=env, now=NOW).ok is True


def test_hmac_custom_timestamp_header_name():
    env = _env(WEBHOOK_TIMESTAMP_HEADER="X-Vendor-Ts")
    body = b'{"evt": 1}'
    headers = _signed_headers("secret", body)
    headers["x-vendor-ts"] = headers.pop("x-webhook-timestamp")
    assert AUTH.verify_hmac("ingest-x", headers, body, env=env, now=NOW).ok is True


def test_hmac_body_only_signature_rejected_by_default():
    """Legacy body-only HMAC is replayable forever, so it is off by default."""
    body = b'{"evt": 1}'
    headers = {"x-hub-signature-256": "sha256=" + _hex_hmac("secret", body)}
    result = AUTH.verify_hmac("ingest-x", headers, body, env=_env(), now=NOW)
    assert result.ok is False
    assert result.reason == "missing_timestamp"


def test_hmac_body_only_signature_accepted_with_legacy_opt_in():
    body = b'{"evt": 1}'
    headers = {"x-hub-signature-256": "sha256=" + _hex_hmac("secret", body)}
    env = _env(WEBHOOK_ALLOW_LEGACY_HMAC="1")
    result = AUTH.verify_hmac("ingest-x", headers, body, env=env, now=NOW)
    assert result.ok is True
    assert result.legacy is True
    assert result.replay_expires_at == NOW + 300


def test_hmac_legacy_opt_in_does_not_accept_wrong_signature():
    headers = {"x-hub-signature-256": "sha256=" + ("0" * 64)}
    env = _env(WEBHOOK_ALLOW_LEGACY_HMAC="1")
    result = AUTH.verify_hmac("ingest-x", headers, b"body", env=env, now=NOW)
    assert result.ok is False
    assert result.reason == "signature_invalid"


def test_hmac_legacy_opt_in_still_enforces_timestamp_when_present():
    """A sender that sends a timestamp is held to the timestamped scheme."""
    body = b'{"evt": 1}'
    headers = {
        "x-hub-signature-256": "sha256=" + _hex_hmac("secret", body),
        "x-webhook-timestamp": str(NOW),
    }
    env = _env(WEBHOOK_ALLOW_LEGACY_HMAC="1")
    result = AUTH.verify_hmac("ingest-x", headers, body, env=env, now=NOW)
    assert result.ok is False
    assert result.reason == "signature_invalid"


def test_hmac_timestamp_is_bound_to_signature():
    """Re-stamping a captured request with a fresh timestamp breaks the MAC."""
    body = b'{"evt": 1}'
    headers = _signed_headers("secret", body, ts=NOW - 3600)
    headers["x-webhook-timestamp"] = str(NOW)
    result = AUTH.verify_hmac("ingest-x", headers, body, env=_env(), now=NOW)
    assert result.ok is False
    assert result.reason == "signature_invalid"


@pytest.mark.parametrize("offset", [301, -301, 86_400])
def test_hmac_rejects_stale_or_future_timestamp(offset):
    body = b'{"evt": 1}'
    headers = _signed_headers("secret", body, ts=NOW - offset)
    result = AUTH.verify_hmac("ingest-x", headers, body, env=_env(), now=NOW)
    assert result.ok is False
    assert result.reason == "timestamp_out_of_window"


@pytest.mark.parametrize("offset", [0, 300, -300])
def test_hmac_accepts_timestamp_at_window_edges(offset):
    body = b'{"evt": 1}'
    headers = _signed_headers("secret", body, ts=NOW - offset)
    assert AUTH.verify_hmac("ingest-x", headers, body, env=_env(), now=NOW).ok is True


def test_hmac_window_is_configurable():
    body = b'{"evt": 1}'
    headers = _signed_headers("secret", body, ts=NOW - 60)
    env = _env(WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS="30")
    result = AUTH.verify_hmac("ingest-x", headers, body, env=env, now=NOW)
    assert result.reason == "timestamp_out_of_window"


@pytest.mark.parametrize("raw", ["", "abc", "-5", "1.5", "+1800000000", "1" * 20, " 12 "])
def test_hmac_rejects_malformed_timestamp(raw):
    body = b'{"evt": 1}'
    headers = _signed_headers("secret", body)
    headers["x-webhook-timestamp"] = raw
    result = AUTH.verify_hmac("ingest-x", headers, body, env=_env(), now=NOW)
    assert result.ok is False
    assert result.reason in {"timestamp_invalid", "missing_timestamp"}


@pytest.mark.parametrize("raw", ["0", "-1", "abc"])
def test_invalid_tolerance_raises(raw):
    with pytest.raises(ValueError, match="WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS"):
        AUTH.timestamp_tolerance_seconds({"WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS": raw})


def test_replay_cache_rejects_second_use_within_window():
    cache = AUTH.ReplayCache(max_entries=10)
    assert cache.check_and_store("k1", expires_at=NOW + 300, now=NOW) is True
    assert cache.check_and_store("k1", expires_at=NOW + 300, now=NOW + 10) is False
    assert cache.check_and_store("k2", expires_at=NOW + 300, now=NOW + 10) is True


def test_replay_cache_forgets_after_expiry():
    cache = AUTH.ReplayCache(max_entries=10)
    assert cache.check_and_store("k1", expires_at=NOW + 300, now=NOW) is True
    assert cache.check_and_store("k1", expires_at=NOW + 900, now=NOW + 301) is True


def test_replay_cache_is_bounded():
    cache = AUTH.ReplayCache(max_entries=3)
    for i in range(10):
        assert cache.check_and_store(f"k{i}", expires_at=NOW + 300, now=NOW) is True
    assert len(cache) == 3


def test_bearer_passes_when_no_token_configured():
    assert AUTH.verify_bearer({}, env={}).ok is True


def test_bearer_rejects_missing_header():
    env = {"WEBHOOK_BEARER_TOKEN": "real"}
    result = AUTH.verify_bearer({}, env=env)
    assert result.ok is False
    assert result.reason == "missing_bearer"


def test_bearer_rejects_wrong_token():
    env = {"WEBHOOK_BEARER_TOKEN": "real"}
    headers = {"authorization": "Bearer fake"}
    result = AUTH.verify_bearer(headers, env=env)
    assert result.ok is False
    assert result.reason == "bearer_invalid"


def test_bearer_accepts_correct_token():
    env = {"WEBHOOK_BEARER_TOKEN": "real"}
    headers = {"authorization": "Bearer real"}
    assert AUTH.verify_bearer(headers, env=env).ok is True


@pytest.mark.parametrize(
    "raw",
    ["not-json", "[]", '{"ingest-x": 1}', '"secret"'],
)
def test_malformed_hmac_secrets_raise(raw):
    """A typo in WEBHOOK_HMAC_SECRETS must not silently disable signing."""
    with pytest.raises(ValueError, match="WEBHOOK_HMAC_SECRETS"):
        AUTH.verify_hmac("anything", {}, b"x", env={"WEBHOOK_HMAC_SECRETS": raw})


def test_auth_not_configured_without_secret_or_bearer():
    assert AUTH.auth_configured_for("ingest-x", env={}) is False
    assert (
        AUTH.auth_configured_for(
            "ingest-x", env={"WEBHOOK_HMAC_SECRETS": json.dumps({"other": "s"})}
        )
        is False
    )


def test_auth_configured_with_skill_secret_or_bearer():
    assert AUTH.auth_configured_for(
        "ingest-x", env={"WEBHOOK_HMAC_SECRETS": json.dumps({"ingest-x": "s"})}
    )
    assert AUTH.auth_configured_for("ingest-x", env={"WEBHOOK_BEARER_TOKEN": "t"})
