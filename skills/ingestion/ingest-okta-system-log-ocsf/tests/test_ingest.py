"""Tests for ingest-okta-system-log-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_okta_system_log", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INGEST
_SPEC.loader.exec_module(_INGEST)

ACCOUNT_CHANGE_CLASS_UID = _INGEST.ACCOUNT_CHANGE_CLASS_UID
ACCOUNT_CHANGE_DISABLE = _INGEST.ACCOUNT_CHANGE_DISABLE
ACCOUNT_CHANGE_LOCK = _INGEST.ACCOUNT_CHANGE_LOCK
ACCOUNT_CHANGE_MFA_ENABLE = _INGEST.ACCOUNT_CHANGE_MFA_ENABLE
ACCOUNT_CHANGE_PASSWORD_CHANGE = _INGEST.ACCOUNT_CHANGE_PASSWORD_CHANGE
AUTH_ACTIVITY_LOGOFF = _INGEST.AUTH_ACTIVITY_LOGOFF
AUTH_ACTIVITY_LOGON = _INGEST.AUTH_ACTIVITY_LOGON
AUTH_ACTIVITY_OTHER = _INGEST.AUTH_ACTIVITY_OTHER
AUTH_CLASS_UID = _INGEST.AUTH_CLASS_UID
OCSF_VERSION = _INGEST.OCSF_VERSION
SKILL_NAME = _INGEST.SKILL_NAME
STATUS_FAILURE = _INGEST.STATUS_FAILURE
STATUS_SUCCESS = _INGEST.STATUS_SUCCESS
USER_ACCESS_ASSIGN = _INGEST.USER_ACCESS_ASSIGN
USER_ACCESS_CLASS_UID = _INGEST.USER_ACCESS_CLASS_UID
USER_ACCESS_REVOKE = _INGEST.USER_ACCESS_REVOKE
_classify_event = _INGEST._classify_event
convert_event = _INGEST.convert_event
ingest = _INGEST.ingest
iter_raw_events = _INGEST.iter_raw_events
parse_ts_ms = _INGEST.parse_ts_ms
severity_to_id = _INGEST.severity_to_id
status_from_outcome = _INGEST.status_from_outcome
validate_event = _INGEST.validate_event

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "okta_system_log_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "okta_system_log_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(**overrides) -> dict:
    event = {
        "uuid": "okta-evt-1",
        "published": "2026-04-13T02:15:00.000Z",
        "eventType": "user.session.start",
        "displayMessage": "User signs in to Okta",
        "severity": "INFO",
        "actor": {
            "id": "00u-user-admin",
            "type": "User",
            "alternateId": "admin@example.com",
            "displayName": "Admin User",
        },
        "client": {
            "ipAddress": "198.51.100.10",
            "userAgent": {
                "rawUserAgent": "Mozilla/5.0",
            },
        },
        "authenticationContext": {
            "externalSessionId": "sess-123",
            "rootSessionId": "root-123",
        },
        "outcome": {"result": "SUCCESS", "reason": None},
        "transaction": {"id": "txn-123"},
        "target": [
            {
                "id": "00u-target",
                "type": "User",
                "alternateId": "alice@example.com",
                "displayName": "Alice Example",
                "detailEntry": None,
            }
        ],
    }
    event.update(overrides)
    return event


class TestParseTs:
    def test_iso_z(self):
        assert parse_ts_ms("2026-04-13T02:15:00.000Z") == 1776046500000

    def test_missing_falls_to_now(self):
        ms = parse_ts_ms(None)
        assert isinstance(ms, int) and ms > 1_700_000_000_000


class TestSeverityAndStatus:
    def test_severity_mapping(self):
        assert severity_to_id("INFO") == 1
        assert severity_to_id("WARN") == 2
        assert severity_to_id("ERROR") == 4

    def test_status_success(self):
        status_id, detail = status_from_outcome({"result": "SUCCESS"})
        assert status_id == STATUS_SUCCESS
        assert detail is None

    def test_status_failure(self):
        status_id, detail = status_from_outcome({"result": "FAILURE", "reason": "INVALID_CREDENTIALS"})
        assert status_id == STATUS_FAILURE
        assert detail == "INVALID_CREDENTIALS"


class TestClassification:
    def test_authentication_routes(self):
        assert _classify_event("user.session.start") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGON)
        assert _classify_event("user.session.end") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGOFF)
        assert _classify_event("user.authentication.auth_via_mfa") == (
            AUTH_CLASS_UID,
            "Authentication",
            AUTH_ACTIVITY_OTHER,
        )
        assert _classify_event("user.mfa.okta_verify.deny_push") == (
            AUTH_CLASS_UID,
            "Authentication",
            AUTH_ACTIVITY_OTHER,
        )
        assert _classify_event("system.push.send_factor_verify_push") == (
            AUTH_CLASS_UID,
            "Authentication",
            AUTH_ACTIVITY_OTHER,
        )

    def test_account_change_routes(self):
        assert _classify_event("user.lifecycle.deactivate") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_DISABLE,
        )
        assert _classify_event("user.account.update_password") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_PASSWORD_CHANGE,
        )
        assert _classify_event("user.account.lock") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_LOCK,
        )
        assert _classify_event("user.mfa.factor.activate") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_MFA_ENABLE,
        )

    def test_user_access_routes(self):
        assert _classify_event("application.user_membership.add") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_ASSIGN,
        )
        assert _classify_event("group.user_membership.remove") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_REVOKE,
        )


class TestValidation:
    def test_valid_event(self):
        ok, reason = validate_event(_event())
        assert ok, reason

    def test_unsupported_event(self):
        ok, reason = validate_event(_event(eventType="system.unknown"))
        assert not ok
        assert "unsupported eventType" in reason


class TestConvert:
    def test_authentication_event(self):
        event = convert_event(_event())
        assert event["class_uid"] == AUTH_CLASS_UID
        assert event["activity_id"] == AUTH_ACTIVITY_LOGON
        assert event["metadata"]["uid"] == "okta-evt-1"
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert event["user"]["email_addr"] == "alice@example.com"
        assert event["actor"]["user"]["email_addr"] == "admin@example.com"
        assert event["session"]["uid"] == "sess-123"
        assert event["src_endpoint"]["ip"] == "198.51.100.10"

    def test_authentication_failure_without_session(self):
        event = convert_event(
            _event(
                uuid="okta-evt-2",
                outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
                authenticationContext={},
            )
        )
        assert event["status_id"] == STATUS_FAILURE
        assert event["status_detail"] == "INVALID_CREDENTIALS"
        assert "session" not in event

    def test_okta_verify_push_send_event(self):
        event = convert_event(
            _event(
                uuid="okta-evt-push-1",
                eventType="system.push.send_factor_verify_push",
                displayMessage="Push notification sent for verification",
                target=[
                    {
                        "id": "00u-target",
                        "type": "User",
                        "alternateId": "alice@example.com",
                        "displayName": "Alice Example",
                        "detailEntry": None,
                    },
                    {
                        "id": "opf-factor",
                        "type": "AuthenticatorEnrollment",
                        "alternateId": "okta_verify",
                        "displayName": "Okta Verify",
                        "detailEntry": "okta_verify",
                    },
                ],
            )
        )
        assert event["class_uid"] == AUTH_CLASS_UID
        assert event["activity_id"] == AUTH_ACTIVITY_OTHER
        assert event["resources"][0]["name"] == "Okta Verify"
        assert event["service"]["name"] == "Okta Verify"

    def test_okta_verify_deny_event(self):
        event = convert_event(
            _event(
                uuid="okta-evt-deny-1",
                eventType="user.mfa.okta_verify.deny_push",
                displayMessage="User rejected Okta push verify",
                outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
                target=[
                    {
                        "id": "00u-target",
                        "type": "User",
                        "alternateId": "alice@example.com",
                        "displayName": "Alice Example",
                        "detailEntry": None,
                    },
                    {
                        "id": "opf-factor",
                        "type": "AuthenticatorEnrollment",
                        "alternateId": "okta_verify",
                        "displayName": "Okta Verify",
                        "detailEntry": "okta_verify",
                    },
                ],
            )
        )
        assert event["class_uid"] == AUTH_CLASS_UID
        assert event["activity_id"] == AUTH_ACTIVITY_OTHER
        assert event["status_id"] == STATUS_FAILURE
        assert event["status_detail"] == "INVALID_CREDENTIALS"

    def test_account_change_event(self):
        event = convert_event(
            _event(
                uuid="okta-evt-3",
                eventType="user.lifecycle.deactivate",
                displayMessage="Deactivate Okta User",
            )
        )
        assert event["class_uid"] == ACCOUNT_CHANGE_CLASS_UID
        assert event["activity_id"] == ACCOUNT_CHANGE_DISABLE
        assert event["user"]["name"] == "alice@example.com"

    def test_user_access_event(self):
        event = convert_event(
            _event(
                uuid="okta-evt-4",
                eventType="application.user_membership.add",
                displayMessage="Add user to app membership",
                target=[
                    {
                        "id": "00u-target",
                        "type": "User",
                        "alternateId": "alice@example.com",
                        "displayName": "Alice Example",
                        "detailEntry": None,
                    },
                    {
                        "id": "0oa-app",
                        "type": "AppInstance",
                        "alternateId": "salesforce",
                        "displayName": "Salesforce",
                        "detailEntry": None,
                    },
                ],
            )
        )
        assert event["class_uid"] == USER_ACCESS_CLASS_UID
        assert event["activity_id"] == USER_ACCESS_ASSIGN
        assert event["privileges"] == ["Salesforce"]
        assert event["resources"] == [{"name": "Salesforce", "type": "AppInstance"}]


class TestIterRawEvents:
    def test_array(self):
        events = list(iter_raw_events([json.dumps([_event(uuid="a"), _event(uuid="b")])]))
        assert [event["uuid"] for event in events] == ["a", "b"]

    def test_event_hook_wrapper(self):
        wrapped = {"data": {"events": [_event(uuid="hook-1"), _event(uuid="hook-2")]}}
        events = list(iter_raw_events([json.dumps(wrapped)]))
        assert [event["uuid"] for event in events] == ["hook-1", "hook-2"]

    def test_ndjson_and_bad_line(self, capsys):
        events = list(iter_raw_events(['{"uuid":"ok","published":"2026-04-13T02:15:00.000Z","eventType":"user.session.start"}', '{"bad"']))
        assert len(events) == 1
        assert events[0]["uuid"] == "ok"
        assert "skipping line" in capsys.readouterr().err


class TestGoldenFixture:
    def test_golden_fixture(self):
        produced = list(ingest([RAW_FIXTURE.read_text()]))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert produced == expected
