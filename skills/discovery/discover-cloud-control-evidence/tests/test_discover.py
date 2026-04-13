"""Tests for discover-cloud-control-evidence."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "discover.py"
_SPEC = importlib.util.spec_from_file_location("discover_cloud_control_evidence", _SRC)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

build_evidence = _MODULE.build_evidence
normalize_inventory = _MODULE.normalize_inventory
to_ocsf_live_evidence = _MODULE.to_ocsf_live_evidence


def _aws_snapshot() -> dict:
    return {
        "inventory_id": "aws-snap-1",
        "collected_at": "2026-04-12T02:00:00Z",
        "aws": {
            "iam": {
                "users": [{"UserName": "alice", "MFAEnabled": True}],
                "roles": [{"RoleName": "ml-runtime-role"}],
            },
            "s3": {
                "buckets": [
                    {
                        "Name": "ml-artifacts",
                        "encrypted": True,
                        "public": False,
                        "logging_enabled": True,
                        "token": "drop-me",
                    }
                ]
            },
            "kms": {"keys": [{"KeyId": "key-1", "RotationEnabled": True}]},
            "cloudtrail": {"trails": [{"Name": "org-trail", "IsLogging": True, "KmsKeyId": "arn:kms"}]},
            "ec2": {
                "instances": [{"InstanceId": "i-123", "PublicIpAddress": "1.2.3.4"}],
                "security_groups": [{"GroupId": "sg-1", "GroupName": "public-sg", "ingress": [{"cidr": "0.0.0.0/0"}]}],
            },
        },
    }


def _multi_cloud_snapshot() -> dict:
    return {
        "snapshot_id": "multi-1",
        "captured_at": "2026-04-12T03:00:00Z",
        "aws": {
            "bedrock": {"custom_models": [{"modelArn": "arn:aws:bedrock:model/guard", "modelName": "guard-model"}]}
        },
        "gcp": {
            "iam": {"service_accounts": [{"email": "svc@example.iam.gserviceaccount.com"}]},
            "logging": {"sinks": [{"name": "org-sink"}]},
            "compute": {"instances": [{"id": "gce-1", "name": "gce-1", "networkInterfaces": [{"accessConfigs": [{}]}]}]},
        },
        "azure": {
            "entra": {"managed_identities": [{"id": "mi-1", "name": "mi-prod"}]},
            "storage": {"accounts": [{"id": "st-1", "name": "stprod", "encrypted": True}]},
            "monitor": {"diagnostic_settings": [{"id": "diag-1", "name": "diag-prod"}]},
            "ai_foundry": {"deployments": [{"id": "dep-1", "name": "chat-prod", "public": True}]},
        },
    }


class TestNormalizeInventory:
    def test_accepts_aws_snapshot(self):
        normalized = normalize_inventory(_aws_snapshot())
        assert normalized["source_kind"] == "cloud-inventory-snapshot"
        assert normalized["providers"] == ["aws"]
        assert len(normalized["assets"]) >= 6

    def test_accepts_multi_cloud_snapshot(self):
        normalized = normalize_inventory(_multi_cloud_snapshot())
        assert normalized["providers"] == ["aws", "azure", "gcp"]
        assert any(asset["provider"] == "azure" for asset in normalized["assets"])
        assert any(asset["provider"] == "gcp" for asset in normalized["assets"])


class TestBuildEvidence:
    def test_builds_pci_and_soc2_controls(self):
        evidence = build_evidence(_aws_snapshot())
        assert evidence["artifact_type"] == "technical-control-evidence"
        assert evidence["frameworks"] == ["PCI DSS 4.0", "SOC 2 Security"]
        assert len(evidence["controls"]) == 8

    def test_drops_secret_like_properties(self):
        normalized = normalize_inventory(_aws_snapshot())
        bucket = next(asset for asset in normalized["assets"] if asset["kind"] == "bucket")
        assert "token" not in bucket

    def test_framework_filter(self):
        evidence = build_evidence(_multi_cloud_snapshot(), ["soc2"])
        assert evidence["frameworks"] == ["SOC 2 Security"]
        assert {control["framework"] for control in evidence["controls"]} == {"SOC 2 Security"}

    def test_deterministic_output(self):
        assert build_evidence(_multi_cloud_snapshot()) == build_evidence(_multi_cloud_snapshot())

    def test_reports_missing_logging_when_absent(self):
        evidence = build_evidence({"aws": {"iam": {"users": [{"UserName": "alice"}]}}}, ["pci"])
        logging_control = next(control for control in evidence["controls"] if control["control_id"] == "inventory.audit-logging")
        assert logging_control["status"] == "missing"

    def test_invalid_input_raises(self):
        try:
            build_evidence({"unexpected": True})
        except ValueError as exc:
            assert "supported provider inventory" in str(exc)
        else:  # pragma: no cover - defensive
            raise AssertionError("expected ValueError")

    def test_can_emit_ocsf_live_evidence_bridge(self):
        event = to_ocsf_live_evidence(build_evidence(_multi_cloud_snapshot(), ["pci"]))
        assert event["category_uid"] == 5
        assert event["class_uid"] == 5040
        assert event["class_name"] == "Live Evidence Info"
        assert event["metadata"]["version"] == "1.8.0"
        assert event["unmapped"]["cloud_security_technical_evidence"]["frameworks"] == ["PCI DSS 4.0"]
