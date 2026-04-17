from __future__ import annotations

import base64
import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INGEST = _load_module(
    "cloud_security_gcp_runner_ingest_handler_test",
    ROOT / "runners" / "gcp-gcs-pubsub-detect" / "src" / "ingest_handler.py",
)
DETECT = _load_module(
    "cloud_security_gcp_runner_detect_handler_test",
    ROOT / "runners" / "gcp-gcs-pubsub-detect" / "src" / "detect_handler.py",
)


class TestGcpGcsPubsubDetectRunner:
    def test_publish_findings_waits_for_pubsub_results(self):
        seen: list[str] = []

        class _FakeFuture:
            def __init__(self, line: str):
                self.line = line

            def result(self):
                seen.append(self.line)
                return "message-id"

        class _FakePublisher:
            def publish(self, topic: str, payload: bytes):
                assert topic == "projects/test/topics/findings"
                return _FakeFuture(payload.decode("utf-8"))

        DETECT._publish_findings(
            _FakePublisher(),
            "projects/test/topics/findings",
            [("line-1", "uid-1"), ("line-2", "uid-2")],
        )

        assert seen == ["line-1", "line-2"]

    def test_ingest_skill_command_requires_env(self, monkeypatch):
        monkeypatch.delenv("INGEST_SKILL_CMD", raising=False)
        try:
            INGEST._skill_command()
        except ValueError as exc:
            assert "INGEST_SKILL_CMD" in str(exc)
        else:
            raise AssertionError("expected INGEST_SKILL_CMD validation failure")

    def test_ingest_detect_topic_requires_env(self, monkeypatch):
        monkeypatch.delenv("DETECT_TOPIC", raising=False)
        try:
            INGEST._detect_topic()
        except ValueError as exc:
            assert "DETECT_TOPIC" in str(exc)
        else:
            raise AssertionError("expected DETECT_TOPIC validation failure")

    def test_detect_extracts_uid_from_finding_info(self):
        record = {"finding_info": {"uid": "det-123"}, "metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "det-123"

    def test_detect_falls_back_to_metadata_uid(self):
        record = {"metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "meta-123"

    def test_detect_falls_back_to_event_uid(self):
        record = {"event_uid": "evt-123"}
        assert DETECT._extract_uid(record) == "evt-123"

    def test_decode_pubsub_event(self):
        payload = "line-1\nline-2\n".encode("utf-8")
        event = {"data": base64.b64encode(payload).decode("ascii")}
        assert DETECT._decode_pubsub_event(event) == ["line-1", "line-2"]

    def test_detect_ttl_days_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("DEDUPE_TTL_DAYS", raising=False)
        assert DETECT._dedupe_ttl_days() == 30

    def test_detect_ttl_days_respects_env(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "14")
        assert DETECT._dedupe_ttl_days() == 14

    def test_detect_ttl_days_rejects_non_integer(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "fast")
        try:
            DETECT._dedupe_ttl_days()
        except ValueError as exc:
            assert "DEDUPE_TTL_DAYS" in str(exc)
        else:
            raise AssertionError("expected ValueError on non-integer DEDUPE_TTL_DAYS")

    def test_detect_ttl_days_rejects_out_of_range(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "0")
        try:
            DETECT._dedupe_ttl_days()
        except ValueError as exc:
            assert "between 1 and 365" in str(exc)
        else:
            raise AssertionError("expected ValueError on out-of-range DEDUPE_TTL_DAYS")

    def test_detect_expires_at_adds_configured_ttl(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "10")
        base = datetime(2026, 4, 17, tzinfo=UTC)
        assert DETECT._expires_at(now=base) == datetime(2026, 4, 27, tzinfo=UTC)
