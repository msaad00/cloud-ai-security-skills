from __future__ import annotations

import base64
import importlib.util
import sys
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
