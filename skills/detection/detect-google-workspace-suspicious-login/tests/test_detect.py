"""Tests for detect-google-workspace-suspicious-login."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    AUTH_CLASS_UID,
    BRUTE_FORCE_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MIN_FAILURES,
    REPO_NAME,
    REPO_VENDOR,
    SKILL_NAME,
    VALID_ACCOUNTS_UID,
    WINDOW_MS,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT = GOLDEN / "google_workspace_suspicious_login_input.ocsf.jsonl"
EXPECTED = GOLDEN / "google_workspace_suspicious_login_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    event_name: str,
    time_ms: int,
    user_uid: str = "workspace-user-1",
    user_name: str = "alice@example.com",
    ip: str = "198.51.100.21",
    session_uid: str = "workspace-login-1",
    suspicious: bool = False,
    status_id: int = 1,
    status_detail: str | None = None,
) -> dict:
    params: dict[str, object] = {"login_type": "google_password"}
    if suspicious:
        params["is_suspicious"] = True
    event = {
        "activity_id": 1,
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": AUTH_CLASS_UID,
        "class_name": "Authentication",
        "type_uid": 300201,
        "severity_id": 2,
        "status_id": status_id,
        "time": time_ms,
        "message": event_name,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": "ingest-google-workspace-login-ocsf"},
            },
        },
        "src_endpoint": {"ip": ip},
        "user": {"uid": user_uid, "name": user_name, "email_addr": user_name},
        "session": {"uid": session_uid},
        "unmapped": {
            "google_workspace_login": {
                "event_name": event_name,
                "event_type": "login",
                "parameters": params,
            }
        },
    }
    if status_detail:
        event["status_detail"] = status_detail
    return event


class TestDetection:
    def test_suspicious_flag_fires(self):
        events = [_event(uid="evt-1", event_name="login_success", time_ms=1000, suspicious=True)]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["metadata"]["product"]["name"] == REPO_NAME
        assert finding["metadata"]["product"]["vendor_name"] == REPO_VENDOR
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        attacks = {item["technique"]["uid"] for item in finding["finding_info"]["attacks"]}
        assert attacks == {BRUTE_FORCE_UID, VALID_ACCOUNTS_UID}
        assert finding["evidence"]["suspicious_flag_events"] == 1

    def test_failure_burst_followed_by_success_fires(self):
        events = [
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2, status_detail="login_failure_invalid_password"),
            _event(uid="evt-2", event_name="login_failure", time_ms=2000, status_id=2, status_detail="login_failure_invalid_password"),
            _event(uid="evt-3", event_name="login_failure", time_ms=3000, status_id=2, status_detail="login_failure_invalid_password"),
            _event(uid="evt-4", event_name="login_success", time_ms=4000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["failure_count"] == MIN_FAILURES
        assert findings[0]["evidence"]["success_count"] == 1

    def test_out_of_order_input_is_sorted(self):
        events = [
            _event(uid="evt-4", event_name="login_success", time_ms=4000),
            _event(uid="evt-2", event_name="login_failure", time_ms=2000, status_id=2),
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2),
            _event(uid="evt-3", event_name="login_failure", time_ms=3000, status_id=2),
        ]
        assert len(list(detect(events))) == 1

    def test_exact_boundary_is_included(self):
        events = [
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2),
            _event(uid="evt-2", event_name="login_failure", time_ms=2000, status_id=2),
            _event(uid="evt-3", event_name="login_failure", time_ms=3000, status_id=2),
            _event(uid="evt-4", event_name="login_success", time_ms=1000 + WINDOW_MS),
        ]
        assert len(list(detect(events))) == 1

    def test_duplicate_event_uid_does_not_double_count(self):
        events = [
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2),
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2),
            _event(uid="evt-2", event_name="login_failure", time_ms=2000, status_id=2),
            _event(uid="evt-3", event_name="login_success", time_ms=3000),
        ]
        assert list(detect(events)) == []

    def test_different_ip_does_not_join_same_user(self):
        events = [
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2, ip="198.51.100.21"),
            _event(uid="evt-2", event_name="login_failure", time_ms=2000, status_id=2, ip="198.51.100.21"),
            _event(uid="evt-3", event_name="login_failure", time_ms=3000, status_id=2, ip="203.0.113.9"),
            _event(uid="evt-4", event_name="login_success", time_ms=4000, ip="203.0.113.9"),
        ]
        assert list(detect(events)) == []

    def test_golden_fixture_matches(self):
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestMetadata:
    def test_coverage_metadata(self):
        metadata = coverage_metadata()
        assert metadata["providers"] == ("google-workspace",)
        assert metadata["thresholds"]["min_failures"] == MIN_FAILURES
        assert set(metadata["attack_coverage"]["google-workspace"]["techniques"]) == {
            BRUTE_FORCE_UID,
            VALID_ACCOUNTS_UID,
        }


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 3002}']))
        assert out == [{"class_uid": 3002}]
        assert "skipping line 1" in capsys.readouterr().err
