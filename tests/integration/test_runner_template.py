from __future__ import annotations

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
    "cloud_security_runner_ingest_handler_test",
    ROOT / "runners" / "aws-s3-sqs-detect" / "src" / "ingest_handler.py",
)
DETECT = _load_module(
    "cloud_security_runner_detect_handler_test",
    ROOT / "runners" / "aws-s3-sqs-detect" / "src" / "detect_handler.py",
)


class TestAwsS3SqsDetectRunner:
    def test_ingest_skill_command_requires_env(self, monkeypatch):
        monkeypatch.delenv("INGEST_SKILL_CMD", raising=False)
        try:
            INGEST._skill_command()
        except ValueError as exc:
            assert "INGEST_SKILL_CMD" in str(exc)
        else:
            raise AssertionError("expected INGEST_SKILL_CMD validation failure")

    def test_ingest_batches_lines_for_sqs_limits(self):
        batches = list(INGEST._batched([str(i) for i in range(23)], size=10))
        assert [len(batch) for batch in batches] == [10, 10, 3]

    def test_detect_extracts_uid_from_finding_info(self):
        record = {"finding_info": {"uid": "det-123"}, "metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "det-123"

    def test_detect_falls_back_to_metadata_uid(self):
        record = {"metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "meta-123"

    def test_detect_falls_back_to_event_uid(self):
        record = {"event_uid": "evt-123"}
        assert DETECT._extract_uid(record) == "evt-123"

    def test_detect_ttl_days_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("DEDUPE_TTL_DAYS", raising=False)
        assert DETECT._dedupe_ttl_days() == 30

    def test_detect_ttl_days_respects_env(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "7")
        assert DETECT._dedupe_ttl_days() == 7

    def test_detect_ttl_days_rejects_non_integer(self, monkeypatch):
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "twelve")
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
        monkeypatch.setenv("DEDUPE_TTL_DAYS", "30")
        base = 1_700_000_000
        assert DETECT._expires_at(now=base) == base + 30 * 86_400

    def test_detect_expires_at_uses_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("DEDUPE_TTL_DAYS", raising=False)
        base = 1_700_000_000
        assert DETECT._expires_at(now=base) == base + 30 * 86_400

    def test_detect_publish_findings_uses_sns_batches(self, monkeypatch):
        seen_batches: list[list[dict[str, str]]] = []

        class _FakeClient:
            def publish_batch(self, **kwargs):
                seen_batches.append(kwargs["PublishBatchRequestEntries"])
                return {"Failed": []}

        monkeypatch.setattr(DETECT, "_sns_client", lambda: _FakeClient())
        monkeypatch.setattr(DETECT, "_sns_topic", lambda: "arn:aws:sns:us-east-1:123:topic")

        records = [(f"line-{idx}", f"uid-{idx}") for idx in range(12)]
        DETECT._publish_findings(records)

        assert [len(batch) for batch in seen_batches] == [10, 2]
        assert seen_batches[0][0]["Subject"] == "skill-finding:uid-0"
