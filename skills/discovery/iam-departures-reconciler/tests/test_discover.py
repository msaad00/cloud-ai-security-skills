"""Tests for the standalone IAM departures reconciler entrypoint."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "discover.py"
_SPEC = importlib.util.spec_from_file_location("iam_departures_reconciler", _SRC)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

build_manifest = _MODULE.build_manifest


class _FakeRecord:
    def __init__(self, email: str, actionable: bool) -> None:
        self.email = email
        self.recipient_account_id = "123456789012"
        self._actionable = actionable
        self.iam_deleted = False
        self.is_rehire = False
        self.iam_last_used_at = None
        self.rehire_date = None
        self.remediation_status = type("_Status", (), {"value": "pending"})()

    def should_remediate(self) -> bool:
        return self._actionable

    def to_dict(self) -> dict[str, str]:
        return {
            "email": self.email,
            "recipient_account_id": self.recipient_account_id,
            "iam_username": self.email.split("@", 1)[0],
            "termination_source": "snowflake",
            "remediation_status": "pending",
        }


class _FakeSource:
    def __init__(self, records: list[_FakeRecord]) -> None:
        self._records = records

    def fetch_departures(self) -> list[_FakeRecord]:
        return list(self._records)


def test_build_manifest_emits_parser_shape(monkeypatch):
    records = [_FakeRecord("alice@example.com", True), _FakeRecord("bob@example.com", False)]
    monkeypatch.setattr(_MODULE, "get_source", lambda name: _FakeSource(records))

    manifest = build_manifest("snowflake")

    assert manifest["source"] == "snowflake"
    assert manifest["total_records"] == 2
    assert manifest["actionable_count"] == 1
    assert manifest["skipped_count"] == 1
    assert manifest["changed"] is True
    assert isinstance(manifest["entries"], list)
    assert manifest["entries"][0]["email"] == "alice@example.com"


def test_build_manifest_reports_no_change_with_same_hash(monkeypatch):
    records = [_FakeRecord("alice@example.com", True)]
    monkeypatch.setattr(_MODULE, "get_source", lambda name: _FakeSource(records))

    initial = build_manifest("snowflake")
    repeated = build_manifest("snowflake", previous_hash=initial["hash"])

    assert repeated["hash"] == initial["hash"]
    assert repeated["changed"] is False
