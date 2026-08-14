from __future__ import annotations

import sys
from pathlib import Path

from botocore.config import Config

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared import aws  # noqa: E402


def test_boto_config_default_max_attempts(monkeypatch):
    monkeypatch.delenv(aws.MAX_ATTEMPTS_ENV, raising=False)
    config = aws.boto_config()
    assert config.retries == {"max_attempts": 8, "mode": "adaptive"}


def test_boto_config_env_override(monkeypatch):
    monkeypatch.setenv(aws.MAX_ATTEMPTS_ENV, "12")
    config = aws.boto_config()
    assert config.retries["max_attempts"] == 12
    assert config.retries["mode"] == "adaptive"


def test_boto_config_explicit_arg_wins(monkeypatch):
    monkeypatch.setenv(aws.MAX_ATTEMPTS_ENV, "12")
    config = aws.boto_config(max_attempts=3)
    assert config.retries["max_attempts"] == 3
    assert config.retries["mode"] == "adaptive"


def test_boto_config_mode_is_adaptive(monkeypatch):
    monkeypatch.delenv(aws.MAX_ATTEMPTS_ENV, raising=False)
    assert aws.boto_config().retries["mode"] == "adaptive"


def test_client_applies_adaptive_config(monkeypatch):
    captured: dict[str, object] = {}

    def fake_client(service_name, **kwargs):
        captured["service_name"] = service_name
        captured["kwargs"] = kwargs
        return "client"

    monkeypatch.setattr(aws.boto3, "client", fake_client)
    monkeypatch.delenv(aws.MAX_ATTEMPTS_ENV, raising=False)

    result = aws.client("s3")
    assert result == "client"
    assert captured["service_name"] == "s3"
    config = captured["kwargs"]["config"]
    assert isinstance(config, Config)
    assert config.retries == {"max_attempts": 8, "mode": "adaptive"}


def test_client_caller_config_merge_wins(monkeypatch):
    captured: dict[str, object] = {}

    def fake_client(service_name, **kwargs):
        captured["kwargs"] = kwargs
        return "client"

    monkeypatch.setattr(aws.boto3, "client", fake_client)
    monkeypatch.delenv(aws.MAX_ATTEMPTS_ENV, raising=False)

    caller = Config(retries={"max_attempts": 2, "mode": "standard"}, region_name="us-west-2")
    aws.client("s3", config=caller)

    merged = captured["kwargs"]["config"]
    assert merged.retries == {"max_attempts": 2, "mode": "standard"}
    assert merged.region_name == "us-west-2"


def test_resource_applies_adaptive_config(monkeypatch):
    captured: dict[str, object] = {}

    def fake_resource(service_name, **kwargs):
        captured["service_name"] = service_name
        captured["kwargs"] = kwargs
        return "resource"

    monkeypatch.setattr(aws.boto3, "resource", fake_resource)
    monkeypatch.delenv(aws.MAX_ATTEMPTS_ENV, raising=False)

    result = aws.resource("dynamodb")
    assert result == "resource"
    assert captured["service_name"] == "dynamodb"
    assert captured["kwargs"]["config"].retries == {"max_attempts": 8, "mode": "adaptive"}


def test_session_client_applies_adaptive_config(monkeypatch):
    captured: dict[str, object] = {}

    class FakeSession:
        def client(self, service_name, **kwargs):
            captured["service_name"] = service_name
            captured["kwargs"] = kwargs
            return "session-client"

    monkeypatch.delenv(aws.MAX_ATTEMPTS_ENV, raising=False)
    result = aws.session_client(FakeSession(), "sts", region_name="eu-west-1")
    assert result == "session-client"
    assert captured["service_name"] == "sts"
    assert captured["kwargs"]["region_name"] == "eu-west-1"
    assert captured["kwargs"]["config"].retries == {"max_attempts": 8, "mode": "adaptive"}
