"""Tests for ingest-databricks-audit-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_databricks_audit", _SRC)
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


def _record(service: str, action: str, **overrides):
    record = {
        "version": "2.0",
        "timestamp": 1700000000000,
        "workspaceId": 1234567890123456,
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {"email": "alice@example.com"},
        "serviceName": service,
        "actionName": action,
        "requestId": "req-1",
        "requestParams": {},
        "response": {"statusCode": 200, "result": ""},
    }
    record.update(overrides)
    return record


def _one_ocsf(service: str, action: str, **overrides) -> dict:
    events = list(ingest([json.dumps(_record(service, action, **overrides))]))
    assert len(events) == 1, f"expected exactly one event for {service}.{action}"
    return events[0]


def _databricks(event: dict) -> dict:
    return event["unmapped"]["databricks"]


# --- Envelope ------------------------------------------------------------


def test_ocsf_envelope_shape():
    event = _one_ocsf(
        "secrets", "getSecret", requestParams={"scope": "prod-vault", "key": "api-key-000"}
    )
    assert event["class_uid"] == API_ACTIVITY_CLASS_UID
    assert event["category_uid"] == 6
    assert event["type_uid"] == 600301
    assert event["activity_id"] == 1
    assert event["metadata"]["version"] == "1.8.0"
    assert event["metadata"]["uid"] == "req-1"
    assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
    assert event["metadata"]["product"]["vendor_name"] == "msaad00/cloud-ai-security-skills"
    assert event["api"]["operation"] == "secrets.getSecret"
    assert event["api"]["service"]["name"] == "databricks.secrets"
    assert event["src_endpoint"]["ip"] == "203.0.113.10"
    assert event["actor"]["user"]["uid"] == "alice@example.com"
    assert event["actor"]["user"]["email_addr"] == "alice@example.com"
    assert _databricks(event)["workspace_id"] == "1234567890123456"


def test_src_endpoint_omitted_without_ip():
    record = _record("secrets", "getSecret", requestParams={"scope": "s", "key": "k"})
    record.pop("sourceIPAddress")
    event = list(ingest([json.dumps(record)]))[0]
    assert "src_endpoint" not in event


# --- Per-operation parsing ----------------------------------------------


def test_cluster_create_init_scripts_from_stringified_json():
    event = _one_ocsf(
        "clusters",
        "create",
        requestParams={
            "cluster_name": "etl",
            "init_scripts": '[{"s3":{"destination":"s3://attacker/init.sh"}}]',
        },
        response={"statusCode": 200, "result": '{"cluster_id":"cluster-abc"}'},
    )
    assert event["api"]["operation"] == "clusters.create"
    cfg = _databricks(event)["cluster_config"]
    assert cfg["cluster_id"] == "cluster-abc"  # from response.result
    assert cfg["cluster_name"] == "etl"
    assert cfg["init_scripts"] == [{"s3": {"destination": "s3://attacker/init.sh"}}]


def test_cluster_edit_uses_request_param_cluster_id():
    event = _one_ocsf(
        "clusters",
        "edit",
        requestParams={"cluster_id": "cluster-def", "init_scripts": "[]"},
    )
    assert event["api"]["operation"] == "clusters.edit"
    assert _databricks(event)["cluster_config"]["cluster_id"] == "cluster-def"


def test_secret_get():
    event = _one_ocsf(
        "secrets", "getSecret", requestParams={"scope": "prod-vault", "key": "api-key-1"}
    )
    block = _databricks(event)
    assert block["secret_scope"] == "prod-vault"
    assert block["secret_key"] == "api-key-1"


def test_mlflow_download_uri():
    event = _one_ocsf(
        "mlflowModelRegistry",
        "getModelVersionDownloadUri",
        requestParams={"name": "fraud-classifier", "version": "5"},
    )
    assert event["api"]["operation"] == "mlflow.getModelVersionDownloadUri"
    block = _databricks(event)
    assert block["model_name"] == "fraud-classifier"
    assert block["model_version"] == "5"


def test_mlflow_transition_carries_target_workspace():
    event = _one_ocsf(
        "mlflowModelRegistry",
        "transitionModelVersionStage",
        requestParams={
            "name": "propensity-scorer",
            "version": "12",
            "stage": "Production",
            "target_workspace_id": "9999999999999999",
        },
    )
    assert event["api"]["operation"] == "mlflow.transitionModelVersionStage"
    block = _databricks(event)
    assert block["target_stage"] == "Production"
    assert block["target_workspace_id"] == "9999999999999999"


def test_token_create_maps_to_slash_operation():
    event = _one_ocsf(
        "accounts",
        "generateDbToken",
        requestParams={"lifetime_seconds": "86400", "comment": "ci"},
        response={"statusCode": 200, "result": '{"tokenInfo":{"tokenId":"tok-1"}}'},
    )
    assert event["api"]["operation"] == "tokens/create"
    block = _databricks(event)
    assert block["token_id"] == "tok-1"
    assert block["comment"] == "ci"
    assert block["lifetime_seconds"] == 86400


def test_unity_catalog_recipient_external_from_auth_type():
    event = _one_ocsf(
        "unityCatalog",
        "createRecipient",
        requestParams={"name": "ext-customer-1", "authentication_type": "TOKEN"},
    )
    assert event["api"]["operation"] == "unityCatalog.CreateRecipient"
    recipient = _databricks(event)["recipient"]
    assert recipient["id"] == "ext-customer-1"
    assert recipient["type"] == "EXTERNAL"


def test_unity_catalog_recipient_databricks_is_internal():
    event = _one_ocsf(
        "unityCatalog",
        "createRecipient",
        requestParams={"name": "int-team", "authentication_type": "DATABRICKS"},
    )
    assert _databricks(event)["recipient"]["type"] == "DATABRICKS"


def test_unity_catalog_share_recipients():
    event = _one_ocsf(
        "unityCatalog",
        "createShare",
        requestParams={"name": "pii-share", "recipients": '["ext-customer-1","ext-customer-2"]'},
    )
    assert event["api"]["operation"] == "unityCatalog.CreateShare"
    share = _databricks(event)["share"]
    assert share["name"] == "pii-share"
    assert share["recipients"] == ["ext-customer-1", "ext-customer-2"]


def test_set_admin_grantee():
    event = _one_ocsf(
        "accounts",
        "setAdmin",
        requestParams={"targetUserName": "alice-promoted@example.com"},
    )
    assert event["api"]["operation"] == "accounts.setAdmin"
    grantee = _databricks(event)["grantee"]
    assert grantee["uid"] == "alice-promoted@example.com"
    assert grantee["email_addr"] == "alice-promoted@example.com"


def test_add_user_to_group():
    event = _one_ocsf(
        "accounts",
        "addUserToGroup",
        requestParams={"group_name": "admins", "targetUserName": "bob@example.com"},
    )
    assert event["api"]["operation"] == "iam.addUserToGroup"
    block = _databricks(event)
    assert block["group_name"] == "admins"
    assert block["grantee"]["uid"] == "bob@example.com"


# --- Status, actor, and defensive parsing --------------------------------


def test_status_mapping_from_status_code():
    ok = _one_ocsf("secrets", "getSecret", requestParams={"scope": "s", "key": "k"})
    assert ok["status_id"] == STATUS_SUCCESS
    bad = _one_ocsf(
        "secrets",
        "getSecret",
        requestParams={"scope": "s", "key": "k"},
        response={"statusCode": 403, "result": ""},
    )
    assert bad["status_id"] == STATUS_FAILURE


def test_actor_type_service_principal_without_at():
    event = _one_ocsf(
        "accounts",
        "generateDbToken",
        userIdentity={"email": "3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
    )
    assert event["actor"]["user"]["type"] == "Service"
    assert "email_addr" not in event["actor"]["user"]


def test_snake_case_system_table_shape_is_accepted():
    record = {
        "timestamp": 1700000000000,
        "workspace_id": 1234567890123456,
        "source_ip_address": "203.0.113.10",
        "user_identity": {"email": "alice@example.com"},
        "service_name": "secrets",
        "action_name": "getSecret",
        "request_id": "req-snake",
        "request_params": {"scope": "prod-vault", "key": "k1"},
        "response": {"status_code": 200, "result": ""},
    }
    event = list(ingest([json.dumps(record)]))[0]
    assert event["metadata"]["uid"] == "req-snake"
    assert event["api"]["operation"] == "secrets.getSecret"
    assert event["src_endpoint"]["ip"] == "203.0.113.10"


def test_unrecognized_action_is_skipped():
    skipped: dict[str, int] = {}
    events = list(ingest([json.dumps(_record("jobs", "runNow"))], skipped_counts=skipped))
    assert events == []
    assert skipped.get("jobs.runNow") == 1


def test_malformed_line_does_not_crash():
    events = list(
        ingest(
            [
                "not json",
                json.dumps(
                    _record("secrets", "getSecret", requestParams={"scope": "s", "key": "k"})
                ),
            ]
        )
    )
    assert len(events) == 1


def test_json_array_input():
    payload = json.dumps(
        [
            _record("secrets", "getSecret", requestParams={"scope": "s", "key": "k1"}),
            _record(
                "secrets", "getSecret", requestId="req-2", requestParams={"scope": "s", "key": "k2"}
            ),
        ]
    )
    events = list(ingest([payload]))
    assert len(events) == 2


def test_native_output_format():
    events = list(
        ingest(
            [json.dumps(_record("secrets", "getSecret", requestParams={"scope": "s", "key": "k"}))],
            output_format="native",
        )
    )
    assert events[0]["schema_mode"] == "native"
    assert events[0]["operation"] == "secrets.getSecret"
    assert events[0]["provider"] == "Databricks"


def test_parse_ts_ms_forms():
    assert parse_ts_ms("2026-08-01T00:00:00.000Z") == 1785542400000
    assert parse_ts_ms(1785542400000) == 1785542400000
    assert parse_ts_ms(1785542400) == 1785542400000


def test_derive_operation_returns_none_for_irrelevant():
    assert derive_operation(_record("jobs", "runNow")) is None
    assert derive_operation({"serviceName": "", "actionName": ""}) is None
