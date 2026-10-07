"""Sink subprocess environment scrubbing."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SINKS_PATH = REPO_ROOT / "runners" / "webhook-receiver" / "src" / "sinks.py"


def _load_sinks():
    spec = importlib.util.spec_from_file_location("webhook_sinks_test", SINKS_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_sink_child_env_drops_wrapper_only_secrets():
    sinks = _load_sinks()
    src = {
        "PATH": "/usr/bin",
        "CLOUD_SECURITY_AUDIT_HMAC_KEY": "canary-hmac",
        "CLOUD_SECURITY_SSE_BEARER_KEYS": "canary-bearer",
        "CLOUD_SECURITY_MCP_AUDIT_LOG": "/x",
        "CLOUD_SECURITY_MCP_TIMEOUT_SECONDS": "5",
        "CLOUD_SECURITY_WEBHOOK_HMAC_SECRET": "canary-wh",
        "WEBHOOK_BEARER_TOKEN": "canary-whb",
        "CLOUD_SECURITY_SNOWFLAKE_ACCOUNT": "acct",
        "CLOUD_SECURITY_S3_BUCKET": "bucket",
    }
    env = sinks._build_child_env(src, "cid-1")

    for leaked in (
        "CLOUD_SECURITY_AUDIT_HMAC_KEY",
        "CLOUD_SECURITY_SSE_BEARER_KEYS",
        "CLOUD_SECURITY_MCP_AUDIT_LOG",
        "CLOUD_SECURITY_MCP_TIMEOUT_SECONDS",
        "CLOUD_SECURITY_WEBHOOK_HMAC_SECRET",
        "WEBHOOK_BEARER_TOKEN",
    ):
        assert leaked not in env, leaked
    assert env["CLOUD_SECURITY_SNOWFLAKE_ACCOUNT"] == "acct"
    assert env["CLOUD_SECURITY_S3_BUCKET"] == "bucket"
    assert env["PATH"] == "/usr/bin"
    assert env["SKILL_CORRELATION_ID"] == "cid-1"


def test_sinks_uses_shared_wrapper_only_rule():
    sinks = _load_sinks()
    import arg_policy

    assert sinks.is_wrapper_only_env is arg_policy.is_wrapper_only_env
