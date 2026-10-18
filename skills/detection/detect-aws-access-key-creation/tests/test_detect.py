"""Tests for detect-aws-access-key-creation."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError  # noqa: E402

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location("detect_aws_access_key_creation_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
ACCESS_KEY_CREATE_OPERATION = MODULE.ACCESS_KEY_CREATE_OPERATION
SUBTECHNIQUE_UID = MODULE.SUBTECHNIQUE_UID
detect = MODULE.detect


def _ct_event(
    *,
    operation: str = "CreateAccessKey",
    success: bool = True,
    target_user: str = "bob",
    actor: str = "AROAEXAMPLEID:alice",
    account_uid: str = "111122223333",
    region: str = "us-east-1",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-cloudtrail-ocsf",
    resource_type: str = "userName",
) -> dict:
    resources = []
    if target_user:
        resources.append({"name": target_user, "type": resource_type})
    return {
        "class_uid": 6003,
        "status_id": 1 if success else 2,
        "time": 1700000000000,
        "metadata": {
            "uid": "evt-1",
            "product": {"feature": {"name": producer}},
        },
        "actor": {"user": {"name": actor}},
        "src_endpoint": {"ip": src_ip},
        "api": {"operation": operation},
        "cloud": {"provider": "AWS", "account": {"uid": account_uid}, "region": region},
        "resources": resources,
    }


def test_accepted_producer_is_cloudtrail():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-cloudtrail-ocsf"})


def test_operation_is_create_access_key_only():
    assert ACCESS_KEY_CREATE_OPERATION == "CreateAccessKey"


def test_fires_on_create_access_key():
    findings = list(detect([_ct_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    attack = finding["finding_info"]["attacks"][0]
    assert attack["sub_technique"]["uid"] == SUBTECHNIQUE_UID
    assert finding["finding_info"]["title"] == "AWS IAM access key created"
    assert any(
        obs["name"] == "target.name" and obs["value"] == "bob" for obs in finding["observables"]
    )


def test_native_output_contains_target_user():
    findings = list(detect([_ct_event(target_user="carol")], output_format="native"))
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["target_user_name"] == "carol"
    assert finding["rule"] == "aws-access-key-creation"


def test_skips_failed_event():
    assert list(detect([_ct_event(success=False)])) == []


def test_skips_unrelated_operation():
    assert list(detect([_ct_event(operation="ListUsers")])) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_ct_event(producer="ingest-okta-system-log-ocsf")]))
    assert findings == []
    assert "non-cloudtrail producer" in capsys.readouterr().err


def test_rejects_missing_target_user():
    with pytest.raises(ContractError, match="no target IAM username"):
        list(detect([_ct_event(target_user="")]))


def test_accepts_resource_type_user():
    findings = list(detect([_ct_event(resource_type="user")]))
    assert len(findings) == 1


def test_rejects_unknown_output_format():
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_ct_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint


def test_finding_uid_is_deterministic():
    event = _ct_event()
    first = list(detect([event]))[0]["finding_info"]["uid"]
    second = list(detect([event]))[0]["finding_info"]["uid"]
    assert first == second
    assert first.startswith("aakc-")


@pytest.mark.parametrize("output_format", ["ocsf", "native"])
def test_preserves_scoped_source_reference_without_payload(output_format):
    event = _ct_event()
    event["unmapped"] = {"cloudtrail": {"request_parameters": {"secret": "do-not-copy"}}}
    event["actor"]["session"] = {"uid": "do-not-copy-session"}
    finding = list(detect([event], output_format=output_format))[0]
    container = finding["evidence"] if output_format == "ocsf" else finding
    assert container["source_event"] == {
        "uid": "evt-1",
        "producer": "ingest-cloudtrail-ocsf",
        "account_uid": "111122223333",
        "region": "us-east-1",
    }
    assert "do-not-copy" not in str(finding)
    assert event["metadata"]["uid"] == "evt-1"


@pytest.mark.parametrize("uid", [None, "", "   "])
@pytest.mark.parametrize("output_format", ["ocsf", "native"])
def test_missing_source_uid_does_not_invent_reference(uid, output_format):
    event = _ct_event()
    event["metadata"]["uid"] = uid
    finding = list(detect([event], output_format=output_format))[0]
    container = finding["evidence"] if output_format == "ocsf" else finding
    assert "source_event" not in container


@pytest.mark.parametrize(
    "uid", [{"secret": "do-not-copy"}, ["do-not-copy"], 42, True, "x" * 1025, "a\nb"]
)
def test_invalid_source_uid_fails_without_disclosing_value(uid):
    event = _ct_event()
    event["metadata"]["uid"] = uid
    with pytest.raises(ContractError, match="invalid source event UID") as exc:
        list(detect([event]))
    assert "do-not-copy" not in str(exc.value)


def test_source_reference_preserves_full_uid_and_recipient_account():
    event = _ct_event(account_uid="444455556666")
    event["actor"]["user"]["account"] = {"uid": "111122223333"}
    event["metadata"]["uid"] = "e" * 1024
    reference = list(detect([event]))[0]["evidence"]["source_event"]
    assert reference["uid"] == "e" * 1024
    assert reference["account_uid"] == "444455556666"
