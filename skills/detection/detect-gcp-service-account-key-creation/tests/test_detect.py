"""Tests for detect-gcp-service-account-key-creation."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location("detect_gcp_service_account_key_creation_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
CREATE_SA_KEY_OPERATION = MODULE.CREATE_SA_KEY_OPERATION
SUBTECHNIQUE_UID = MODULE.SUBTECHNIQUE_UID
detect = MODULE.detect


def _event(
    *,
    operation: str = "google.iam.admin.v1.CreateServiceAccountKey",
    service: str = "iam.googleapis.com",
    success: bool = True,
    target_service_account: str = "sa-deploy@my-project.iam.gserviceaccount.com",
    actor_name: str = "alice@example.com",
    project_uid: str = "my-project",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-gcp-audit-ocsf",
    resource_type: str = "service_account",
) -> dict:
    resources = []
    if target_service_account:
        resources.append(
            {
                "name": f"projects/-/serviceAccounts/{target_service_account}",
                "type": resource_type,
            }
        )
    return {
        "class_uid": 6003,
        "status_id": 1 if success else 2,
        "time": 1775797200000,
        "metadata": {"uid": "evt-1", "product": {"feature": {"name": producer}}},
        "actor": {"user": {"name": actor_name}},
        "src_endpoint": {"ip": src_ip},
        "api": {"operation": operation, "service": {"name": service}},
        "cloud": {"provider": "GCP", "account": {"uid": project_uid}},
        "resources": resources,
    }


def test_accepted_producer_is_gcp_audit():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-gcp-audit-ocsf"})


def test_operation_is_create_service_account_key_only():
    assert CREATE_SA_KEY_OPERATION == "google.iam.admin.v1.CreateServiceAccountKey"


def test_fires_on_create_service_account_key():
    findings = list(detect([_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    attack = finding["finding_info"]["attacks"][0]
    assert attack["sub_technique_uid"] == SUBTECHNIQUE_UID
    assert finding["finding_info"]["title"] == "GCP service account key created"
    assert any(
        obs["name"] == "target.name" and obs["value"] == "sa-deploy@my-project.iam.gserviceaccount.com"
        for obs in finding["observables"]
    )


def test_native_output_contains_target_service_account():
    findings = list(detect([_event(target_service_account="sa-ci@my-project.iam.gserviceaccount.com")], output_format="native"))
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["target_service_account"] == "sa-ci@my-project.iam.gserviceaccount.com"
    assert finding["rule"] == "gcp-service-account-key-creation"


def test_skips_failed_event():
    assert list(detect([_event(success=False)])) == []


def test_skips_unrelated_operation():
    assert list(detect([_event(operation="google.iam.admin.v1.DeleteServiceAccountKey")])) == []


def test_skips_wrong_service():
    assert list(detect([_event(service="storage.googleapis.com")])) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_event(producer="ingest-cloudtrail-ocsf")]))
    assert findings == []
    assert "non-gcp-audit producer" in capsys.readouterr().err


def test_skips_missing_target_service_account(capsys):
    findings = list(detect([_event(target_service_account="")]))
    assert findings == []
    assert "no target service account" in capsys.readouterr().err


def test_accepts_raw_service_account_resource_name_without_prefix():
    findings = list(
        detect(
            [
                {
                    **_event(),
                    "resources": [{"name": "sa-deploy@my-project.iam.gserviceaccount.com", "type": "service_account"}],
                }
            ]
        )
    )
    assert len(findings) == 1


def test_rejects_unknown_output_format():
    with pytest.raises(ValueError, match="unsupported output_format"):
        list(detect([_event()], output_format="weird"))


def test_finding_uid_is_deterministic():
    event = _event()
    first = list(detect([event]))[0]["finding_info"]["uid"]
    second = list(detect([event]))[0]["finding_info"]["uid"]
    assert first == second
    assert first.startswith("gsakc-")
