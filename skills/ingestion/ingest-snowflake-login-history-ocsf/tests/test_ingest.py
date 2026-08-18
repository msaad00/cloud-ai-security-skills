"""Tests for ingest-snowflake-login-history-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_snowflake_login_history", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INGEST
_SPEC.loader.exec_module(_INGEST)

ingest = _INGEST.ingest
iter_raw_rows = _INGEST.iter_raw_rows
parse_ts_ms = _INGEST.parse_ts_ms
SKILL_NAME = _INGEST.SKILL_NAME
AUTH_CLASS_UID = _INGEST.AUTH_CLASS_UID
AUTH_TYPE_UID = _INGEST.AUTH_TYPE_UID
STATUS_SUCCESS = _INGEST.STATUS_SUCCESS
STATUS_FAILURE = _INGEST.STATUS_FAILURE


def _row(**overrides):
    row = {
        "EVENT_ID": 100001,
        "EVENT_TIMESTAMP": "2026-08-17T14:00:00.000Z",
        "EVENT_TYPE": "LOGIN",
        "USER_NAME": "MARK",
        "CLIENT_IP": "203.0.113.10",
        "REPORTED_CLIENT_TYPE": "SNOWFLAKE_UI",
        "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
        "SECOND_AUTHENTICATION_FACTOR": "DUO",
        "IS_SUCCESS": "NO",
        "ERROR_CODE": 390127,
        "ERROR_MESSAGE": "Failed to authenticate with the second authentication factor.",
    }
    row.update(overrides)
    return row


def _one_ocsf(**overrides) -> dict:
    events = list(ingest([json.dumps(_row(**overrides))]))
    assert len(events) == 1, "expected exactly one event"
    return events[0]


def _snowflake(event: dict) -> dict:
    return event["unmapped"]["snowflake"]


# --- Envelope ------------------------------------------------------------


def test_ocsf_envelope_shape():
    event = _one_ocsf()
    assert event["class_uid"] == AUTH_CLASS_UID == 3002
    assert event["class_name"] == "Authentication"
    assert event["category_uid"] == 3
    assert event["category_name"] == "Identity & Access Management"
    assert event["type_uid"] == AUTH_TYPE_UID == 300201
    assert event["activity_id"] == 1  # Logon
    assert event["metadata"]["version"] == "1.8.0"
    assert event["metadata"]["uid"] == "100001"
    assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
    assert event["metadata"]["product"]["vendor_name"] == "msaad00/cloud-ai-security-skills"
    assert event["src_endpoint"]["ip"] == "203.0.113.10"
    assert event["actor"]["user"]["uid"] == "MARK"
    assert _snowflake(event)["event_id"] == "100001"


def test_src_endpoint_omitted_without_client_ip():
    event = _one_ocsf(CLIENT_IP=None)
    assert "src_endpoint" not in event


# --- Authentication block ------------------------------------------------


def test_failed_mfa_block_shape():
    block = _snowflake(_one_ocsf())
    assert block["authentication_method"] == "DUO"
    assert block["is_success"] is False
    assert block["error_code"] == "390127"
    assert block["first_authentication_factor"] == "PASSWORD"
    assert block["second_authentication_factor"] == "DUO"
    assert block["event_type"] == "LOGIN"
    assert block["reported_client_type"] == "SNOWFLAKE_UI"


def test_is_success_varchar_yes_maps_true_and_status_success():
    event = _one_ocsf(IS_SUCCESS="YES", ERROR_CODE=None, ERROR_MESSAGE=None)
    assert _snowflake(event)["is_success"] is True
    assert event["status_id"] == STATUS_SUCCESS
    assert event["severity_id"] == 1  # informational


def test_is_success_varchar_no_maps_false_and_status_failure():
    event = _one_ocsf(IS_SUCCESS="NO")
    assert _snowflake(event)["is_success"] is False
    assert event["status_id"] == STATUS_FAILURE
    assert event["severity_id"] == 2  # low


def test_is_success_accepts_native_boolean():
    assert _snowflake(_one_ocsf(IS_SUCCESS=True))["is_success"] is True
    assert _snowflake(_one_ocsf(IS_SUCCESS=False))["is_success"] is False


def test_authentication_method_prefers_second_factor():
    # Second factor (the MFA factor) is what the detector reasons over.
    block = _snowflake(
        _one_ocsf(FIRST_AUTHENTICATION_FACTOR="PASSWORD", SECOND_AUTHENTICATION_FACTOR="WEBAUTHN")
    )
    assert block["authentication_method"] == "WEBAUTHN"


def test_authentication_method_falls_back_to_first_factor():
    block = _snowflake(
        _one_ocsf(FIRST_AUTHENTICATION_FACTOR="KEY_PAIR", SECOND_AUTHENTICATION_FACTOR=None)
    )
    assert block["authentication_method"] == "KEY_PAIR"
    assert "second_authentication_factor" not in block


def test_error_code_number_serialized_as_float_is_normalized():
    assert _snowflake(_one_ocsf(ERROR_CODE=390127.0))["error_code"] == "390127"


def test_error_code_null_yields_empty_string():
    event = _one_ocsf(IS_SUCCESS="YES", ERROR_CODE=None)
    assert _snowflake(event)["error_code"] == ""


# --- Actor ---------------------------------------------------------------


def test_actor_type_from_user_type_enrichment():
    svc = _one_ocsf(USER_TYPE="SERVICE")
    assert svc["actor"]["user"]["type"] == "Service"
    person = _one_ocsf(USER_TYPE="PERSON")
    assert person["actor"]["user"]["type"] == "User"
    default = _one_ocsf()
    assert default["actor"]["user"]["type"] == "User"


def test_actor_name_prefers_email_enrichment():
    ev = _one_ocsf(USER_EMAIL="mark@example.com")
    assert ev["actor"]["user"]["name"] == "mark@example.com"
    assert ev["actor"]["user"]["email_addr"] == "mark@example.com"
    ev2 = _one_ocsf()
    assert ev2["actor"]["user"]["name"] == "MARK"
    assert "email_addr" not in ev2["actor"]["user"]


# --- Row emission / defensive parsing ------------------------------------


def test_every_login_row_is_emitted_success_and_failure():
    rows = [
        json.dumps(_row(EVENT_ID=1, IS_SUCCESS="NO")),
        json.dumps(_row(EVENT_ID=2, IS_SUCCESS="YES", ERROR_CODE=None)),
    ]
    events = list(ingest(rows))
    assert len(events) == 2


def test_row_without_user_name_is_skipped_and_counted():
    skipped: dict[str, int] = {}
    events = list(ingest([json.dumps(_row(USER_NAME=""))], skipped_counts=skipped))
    assert events == []
    assert skipped.get("no_user") == 1


def test_lowercase_columns_are_accepted():
    raw = {
        "event_id": 55,
        "event_timestamp": "2026-08-17T14:00:00.000Z",
        "user_name": "carol",
        "client_ip": "10.0.0.9",
        "second_authentication_factor": "TOTP",
        "is_success": "NO",
        "error_code": 390127,
    }
    events = list(ingest([json.dumps(raw)]))
    assert len(events) == 1
    assert events[0]["actor"]["user"]["uid"] == "carol"
    assert _snowflake(events[0])["authentication_method"] == "TOTP"


def test_malformed_line_does_not_crash():
    events = list(ingest(["not json", json.dumps(_row())]))
    assert len(events) == 1


def test_json_array_input():
    payload = json.dumps([_row(EVENT_ID=1), _row(EVENT_ID=2)])
    events = list(ingest([payload]))
    assert len(events) == 2


def test_native_output_format():
    events = list(ingest([json.dumps(_row())], output_format="native"))
    assert events[0]["schema_mode"] == "native"
    assert events[0]["record_type"] == "authentication"
    assert events[0]["provider"] == "Snowflake"
    assert events[0]["status"] == "failure"
    assert events[0]["unmapped"]["snowflake"]["authentication_method"] == "DUO"


def test_parse_ts_ms_forms():
    assert parse_ts_ms("2026-08-17T14:00:00.000Z") == 1786975200000
    assert parse_ts_ms(1786975200000) == 1786975200000
    assert parse_ts_ms(1786975200) == 1786975200000


def test_unsupported_output_format_raises():
    try:
        list(ingest([json.dumps(_row())], output_format="csv"))
    except ValueError as exc:
        assert "unsupported output_format" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")
