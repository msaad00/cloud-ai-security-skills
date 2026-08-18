"""Tests for ingest-snowflake-query-history-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_snowflake_query_history", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INGEST
_SPEC.loader.exec_module(_INGEST)

ingest = _INGEST.ingest
derive_operation = _INGEST.derive_operation
iter_raw_rows = _INGEST.iter_raw_rows
parse_ts_ms = _INGEST.parse_ts_ms
SKILL_NAME = _INGEST.SKILL_NAME
API_ACTIVITY_CLASS_UID = _INGEST.API_ACTIVITY_CLASS_UID
STATUS_SUCCESS = _INGEST.STATUS_SUCCESS
STATUS_FAILURE = _INGEST.STATUS_FAILURE


def _row(query_text: str, **overrides):
    row = {
        "QUERY_ID": "q-1",
        "QUERY_TEXT": query_text,
        "USER_NAME": "ACCOUNTADMIN",
        "START_TIME": "2026-08-01T00:00:00.000Z",
        "EXECUTION_STATUS": "success",
    }
    row.update(overrides)
    return row


def _one_ocsf(query_text: str, **overrides) -> dict:
    events = list(ingest([json.dumps(_row(query_text, **overrides))]))
    assert len(events) == 1, f"expected exactly one event for {query_text!r}"
    return events[0]


def _snowflake(event: dict) -> dict:
    return event["unmapped"]["snowflake"]


# --- Envelope ------------------------------------------------------------


def test_ocsf_envelope_shape():
    event = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER ATTACKER", CLIENT_IP="203.0.113.10")
    assert event["class_uid"] == API_ACTIVITY_CLASS_UID
    assert event["category_uid"] == 6
    assert event["type_uid"] == 600301
    assert event["activity_id"] == 1
    assert event["metadata"]["version"] == "1.8.0"
    assert event["metadata"]["uid"] == "q-1"
    assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
    assert event["metadata"]["product"]["vendor_name"] == "msaad00/cloud-ai-security-skills"
    assert event["api"]["service"]["name"] == "snowflake.warehouse"
    assert event["src_endpoint"]["ip"] == "203.0.113.10"
    assert event["actor"]["user"]["uid"] == "ACCOUNTADMIN"
    assert _snowflake(event)["query_id"] == "q-1"


def test_src_endpoint_omitted_without_client_ip():
    event = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER ATTACKER")
    assert "src_endpoint" not in event


# --- Per-operation parsing ----------------------------------------------


def test_grant_role_to_user():
    event = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER ATTACKER_USER")
    assert event["api"]["operation"] == "GRANT_ROLE"
    block = _snowflake(event)
    assert block["granted_role"] == "ACCOUNTADMIN"
    assert block["grantee_user"] == "ATTACKER_USER"
    assert "grantee_role" not in block


def test_grant_role_to_role():
    event = _one_ocsf("GRANT ROLE SECURITYADMIN TO ROLE CUSTOM_ADMIN")
    assert _snowflake(event)["grantee_role"] == "CUSTOM_ADMIN"


def test_alter_user_rsa_key_slots():
    e1 = _one_ocsf("ALTER USER BOB SET RSA_PUBLIC_KEY='MIIB'")
    b1 = _snowflake(e1)
    assert e1["api"]["operation"] == "ALTER_USER"
    assert b1["target_user"] == "BOB"
    assert b1["statement_kind"] == "ALTER_USER_SET_RSA_PUBLIC_KEY"
    assert b1["rsa_public_key_set"] is True

    e2 = _one_ocsf("ALTER USER CAROL SET RSA_PUBLIC_KEY_2='MIIB'")
    assert _snowflake(e2)["statement_kind"] == "ALTER_USER_SET_RSA_PUBLIC_KEY_2"


def test_alter_user_non_key_is_emitted_but_not_a_key_slot():
    event = _one_ocsf("ALTER USER BOB SET DEFAULT_ROLE = ANALYST")
    block = _snowflake(event)
    assert block["statement_kind"] == "ALTER_USER_SET_DEFAULT_ROLE"
    assert block["rsa_public_key_set"] is False


def test_alter_account_unset_network_policy():
    event = _one_ocsf("ALTER ACCOUNT UNSET NETWORK_POLICY")
    assert event["api"]["operation"] == "ALTER_ACCOUNT"
    block = _snowflake(event)
    assert block["operation_kind"] == "account_network_policy_unset"
    assert block["policy_name"] == ""


def test_alter_network_policy_wildcard():
    event = _one_ocsf("ALTER NETWORK POLICY PROD SET ALLOWED_IP_LIST=('0.0.0.0/0')")
    assert event["api"]["operation"] == "ALTER_NETWORK_POLICY"
    block = _snowflake(event)
    assert block["policy_name"] == "PROD"
    assert block["operation_kind"] == "set_allowed_ip_list"
    assert block["allowed_ip_list"] == ["0.0.0.0/0"]
    assert block["blocked_ip_list"] == []


def test_alter_database_replication_and_failover():
    e1 = _one_ocsf("ALTER DATABASE PROD ENABLE REPLICATION TO ACCOUNTS A_1, B_2")
    assert e1["api"]["operation"] == "ALTER_DATABASE_ENABLE_REPLICATION"
    b1 = _snowflake(e1)
    assert b1["database_name"] == "PROD"
    assert b1["target_accounts"] == ["A_1", "B_2"]

    e2 = _one_ocsf("ALTER DATABASE PROD ENABLE FAILOVER TO ACCOUNTS ROGUE_Z")
    assert e2["api"]["operation"] == "ALTER_DATABASE_ENABLE_FAILOVER"
    assert _snowflake(e2)["operation_kind"] == "alter_database_enable_failover"


def test_session_policy_timeouts():
    event = _one_ocsf(
        "ALTER SESSION POLICY P SET SESSION_IDLE_TIMEOUT_MINS = 240 "
        "SESSION_UI_IDLE_TIMEOUT_MINS = 120"
    )
    assert event["api"]["operation"] == "ALTER_SESSION_POLICY"
    block = _snowflake(event)
    assert block["session_idle_timeout_mins"] == 240
    assert block["session_ui_idle_timeout_mins"] == 120


def test_create_session_policy():
    event = _one_ocsf("CREATE SESSION POLICY LAX SESSION_IDLE_TIMEOUT_MINS = 120")
    assert event["api"]["operation"] == "CREATE_SESSION_POLICY"


def test_create_and_alter_share():
    e1 = _one_ocsf("CREATE SHARE PARTNER_SHARE")
    assert e1["api"]["operation"] == "CREATE_SHARE"
    assert _snowflake(e1)["operation_kind"] == "create_share"

    e2 = _one_ocsf("ALTER SHARE PARTNER_SHARE ADD ACCOUNTS = EXT_A, EXT_B")
    assert e2["api"]["operation"] == "ALTER_SHARE_ADD_ACCOUNTS"
    assert _snowflake(e2)["target_accounts"] == ["EXT_A", "EXT_B"]


def test_warehouse_size_chaining_across_stream():
    rows = [
        json.dumps(_row("ALTER WAREHOUSE WH SET WAREHOUSE_SIZE = 'SMALL'", QUERY_ID="r1")),
        json.dumps(_row("ALTER WAREHOUSE WH SET WAREHOUSE_SIZE = 'MEDIUM'", QUERY_ID="r2")),
    ]
    events = list(ingest(rows))
    assert _snowflake(events[0])["warehouse_size_from"] == "XSMALL"  # seeded default
    assert _snowflake(events[0])["warehouse_size_to"] == "SMALL"
    assert _snowflake(events[1])["warehouse_size_from"] == "SMALL"  # chained
    assert _snowflake(events[1])["warehouse_size_to"] == "MEDIUM"


def test_warehouse_size_alias_normalization():
    event = _one_ocsf("ALTER WAREHOUSE WH SET WAREHOUSE_SIZE = '2X-Large'")
    assert _snowflake(event)["warehouse_size_to"] == "X2LARGE"


def test_alter_warehouse_non_resize_is_skipped():
    assert list(ingest([json.dumps(_row("ALTER WAREHOUSE WH SET AUTO_SUSPEND = 60"))])) == []


def test_copy_into_location_is_egress_but_copy_into_table_is_not():
    egress = _one_ocsf(
        "COPY INTO @s3_one FROM analytics.public.customers",
        QUERY_TYPE="UNLOAD",
        BYTES_SCANNED=2500000000,
        ROWS_UNLOADED=250000,
    )
    assert egress["api"]["operation"] == "COPY_INTO_LOCATION"
    block = _snowflake(egress)
    assert block["stage_name"] == "@s3_one"
    assert block["bytes_scanned"] == 2500000000
    assert block["rows_unloaded"] == 250000

    load = list(
        ingest(
            [json.dumps(_row("COPY INTO analytics.public.staging FROM @stage", QUERY_TYPE="COPY"))]
        )
    )
    assert load == []


def test_get_statement_is_egress():
    event = _one_ocsf("GET @mystage/report.csv file:///tmp/", QUERY_TYPE="GET_FILES")
    assert event["api"]["operation"] == "GET"
    assert _snowflake(event)["stage_name"] == "@mystage/report.csv"


# --- Status, actor, and defensive parsing --------------------------------


def test_execution_status_mapping():
    ok = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER X", EXECUTION_STATUS="success")
    assert ok["status_id"] == STATUS_SUCCESS
    for bad in ("fail", "incident", "failed_with_incident"):
        ev = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER X", EXECUTION_STATUS=bad)
        assert ev["status_id"] == STATUS_FAILURE


def test_actor_type_from_user_type_enrichment():
    svc = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER X", USER_TYPE="SERVICE")
    assert svc["actor"]["user"]["type"] == "Service"
    person = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER X", USER_TYPE="PERSON")
    assert person["actor"]["user"]["type"] == "User"
    default = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER X")
    assert default["actor"]["user"]["type"] == "User"


def test_actor_name_prefers_email_enrichment():
    ev = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER X", USER_EMAIL="a@example.com")
    assert ev["actor"]["user"]["name"] == "a@example.com"
    ev2 = _one_ocsf("GRANT ROLE ACCOUNTADMIN TO USER X")
    assert ev2["actor"]["user"]["name"] == "ACCOUNTADMIN"


def test_unrecognized_statement_is_skipped():
    skipped: dict[str, int] = {}
    events = list(
        ingest([json.dumps(_row("SELECT 1", QUERY_TYPE="SELECT"))], skipped_counts=skipped)
    )
    assert events == []
    assert skipped.get("SELECT") == 1


def test_malformed_line_does_not_crash():
    events = list(ingest(["not json", json.dumps(_row("GRANT ROLE ACCOUNTADMIN TO USER X"))]))
    assert len(events) == 1


def test_json_array_input():
    payload = json.dumps([_row("CREATE SHARE S1"), _row("CREATE SHARE S2", QUERY_ID="q-2")])
    events = list(ingest([payload]))
    assert len(events) == 2


def test_native_output_format():
    events = list(
        ingest([json.dumps(_row("GRANT ROLE ACCOUNTADMIN TO USER X"))], output_format="native")
    )
    assert events[0]["schema_mode"] == "native"
    assert events[0]["operation"] == "GRANT_ROLE"
    assert events[0]["provider"] == "Snowflake"


def test_multiline_query_text_parses():
    event = _one_ocsf("ALTER USER BOB\n  SET RSA_PUBLIC_KEY='MIIB'")
    assert event["api"]["operation"] == "ALTER_USER"


def test_parse_ts_ms_forms():
    assert parse_ts_ms("2026-08-01T00:00:00.000Z") == 1785542400000
    assert parse_ts_ms(1785542400000) == 1785542400000
    assert parse_ts_ms(1785542400) == 1785542400000


def test_derive_operation_returns_none_for_irrelevant():
    assert derive_operation({"QUERY_TEXT": "DROP TABLE t"}, {}) is None
    assert derive_operation({"QUERY_TEXT": ""}, {}) is None
