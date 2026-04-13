"""Tests for detect-okta-mfa-fatigue."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    AUTH_CLASS_UID,
    CHALLENGE_EVENT_TYPES,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    GENERIC_MFA_EVENT_TYPE,
    MIN_CHALLENGES,
    MIN_DENIALS,
    MIN_RELEVANT_EVENTS,
    MITRE_TECHNIQUE_UID,
    OKTA_INGEST_SKILL,
    REPO_NAME,
    REPO_VENDOR,
    SEVERITY_HIGH,
    SKILL_NAME,
    STATUS_FAILURE,
    WINDOW_MS,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT = GOLDEN / "okta_mfa_fatigue_input.ocsf.jsonl"
EXPECTED = GOLDEN / "okta_mfa_fatigue_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    event_type: str,
    time_ms: int,
    user_uid: str = "00u-alice",
    user_name: str = "alice@example.com",
    status_id: int = 1,
    status_detail: str | None = None,
    ip: str = "198.51.100.25",
    session_uid: str = "sess-okta-1",
    resource_name: str = "Okta Verify",
) -> dict:
    event = {
        "activity_id": 99,
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": AUTH_CLASS_UID,
        "class_name": "Authentication",
        "type_uid": 300299,
        "severity_id": 2,
        "status_id": status_id,
        "time": time_ms,
        "message": event_type,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": OKTA_INGEST_SKILL},
            },
        },
        "src_endpoint": {"ip": ip},
        "user": {"uid": user_uid, "name": user_name, "email_addr": user_name},
        "session": {"uid": session_uid},
        "unmapped": {"okta": {"event_type": event_type}},
    }
    if status_detail:
        event["status_detail"] = status_detail
    if resource_name:
        event["resources"] = [{"name": resource_name, "type": "AuthenticatorEnrollment"}]
        event["service"] = {"name": resource_name}
    return event


class TestDetection:
    def test_repeated_push_denials_fire(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
                status_detail="INVALID_CREDENTIALS",
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["name"] == REPO_NAME
        assert finding["metadata"]["product"]["vendor_name"] == REPO_VENDOR
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["uid"] == finding["finding_info"]["uid"]
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert finding["evidence"]["challenge_events"] == 2
        assert finding["evidence"]["denial_events"] == 1

    def test_oie_generic_failure_path_fires_only_for_okta_verify(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type=GENERIC_MFA_EVENT_TYPE,
                time_ms=3000,
                status_id=STATUS_FAILURE,
                status_detail="INVALID_CREDENTIALS",
                resource_name="Okta Verify",
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_oie_generic_failure_without_okta_verify_is_ignored(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type=GENERIC_MFA_EVENT_TYPE,
                time_ms=3000,
                status_id=STATUS_FAILURE,
                status_detail="INVALID_CREDENTIALS",
                resource_name="WebAuthn",
            ),
        ]
        assert list(detect(events)) == []

    def test_requires_denial_signal(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(uid="evt-3", event_type="system.push.send_factor_verify_push", time_ms=3000),
        ]
        assert list(detect(events)) == []

    def test_duplicate_event_uid_does_not_inflate_counts(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(
                uid="evt-2",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=2000,
                status_id=STATUS_FAILURE,
            ),
        ]
        assert list(detect(events)) == []

    def test_out_of_order_events_are_sorted(self):
        events = [
            _event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
            ),
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
        ]
        assert len(list(detect(events))) == 1

    def test_quiet_period_starts_new_burst(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
            ),
            _event(
                uid="evt-4",
                event_type="system.push.send_factor_verify_push",
                time_ms=3000 + WINDOW_MS + 1,
                session_uid="sess-okta-2",
            ),
            _event(
                uid="evt-5",
                event_type="system.push.send_factor_verify_push",
                time_ms=4000 + WINDOW_MS,
                session_uid="sess-okta-2",
            ),
            _event(
                uid="evt-6",
                event_type="user.mfa.okta_verify.deny_push_upgrade_needed",
                time_ms=5000 + WINDOW_MS,
                session_uid="sess-okta-2",
                status_id=STATUS_FAILURE,
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

    def test_golden_fixture_matches(self):
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestMetadata:
    def test_coverage_metadata(self):
        metadata = coverage_metadata()
        assert metadata["providers"] == ("okta",)
        assert metadata["thresholds"]["min_relevant_events"] == MIN_RELEVANT_EVENTS
        assert metadata["thresholds"]["min_challenges"] == MIN_CHALLENGES
        assert metadata["thresholds"]["min_denials"] == MIN_DENIALS
        assert CHALLENGE_EVENT_TYPES.issubset(set(metadata["attack_coverage"]["okta"]["anchor_event_types"]))


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 3002}']))
        assert out == [{"class_uid": 3002}]
        assert "skipping line 1" in capsys.readouterr().err
