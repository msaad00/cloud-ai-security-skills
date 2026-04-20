"""Tests for remediate-aws-sg-revoke."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    DEFAULT_INTENTIONALLY_OPEN_TAG,
    DEFAULT_PROTECTED_SG_NAME_PREFIXES,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_NO_SG,
    STATUS_SKIPPED_PROTECTED,
    STATUS_SUCCESS,
    STATUS_WOULD_VIOLATE_PROTECTED,
    Target,
    check_apply_gate,
    is_protected_sg,
    parse_targets,
    run,
)


def _finding(
    *,
    sg_id: str = "sg-rogue",
    sg_name: str = "web-tier",
    cidrs: list[str] | None = None,
    ports: list[int] | None = None,
    omit_sg_id: bool = False,
) -> dict:
    cidrs = cidrs if cidrs is not None else ["0.0.0.0/0"]
    ports = ports if ports is not None else [22]
    obs: list[dict] = [
        {"name": "cloud.provider", "type": "Other", "value": "AWS"},
        {"name": "actor.name", "type": "Other", "value": "alice"},
        {"name": "api.operation", "type": "Other", "value": "AuthorizeSecurityGroupIngress"},
        {"name": "rule", "type": "Other", "value": "open-security-group-ingress"},
        {"name": "target.name", "type": "Other", "value": sg_name},
        {"name": "target.type", "type": "Other", "value": "SecurityGroup"},
        {"name": "account.uid", "type": "Other", "value": "111122223333"},
        {"name": "region", "type": "Other", "value": "us-east-1"},
    ]
    if not omit_sg_id:
        obs.append({"name": "target.uid", "type": "Other", "value": sg_id})
    for c in cidrs:
        obs.append({"name": "permission.cidr", "type": "Other", "value": c})
    for p in ports:
        obs.append({"name": "permission.port", "type": "Other", "value": str(p)})
    return {
        "class_uid": 2004,
        "metadata": {"uid": "find-1",
                     "product": {"feature": {"name": "detect-aws-open-security-group"}}},
        "finding_info": {"uid": "find-1"},
        "observables": obs,
    }


@dataclass
class _FakeAudit:
    writes: list[dict] = field(default_factory=list)

    def record(self, *, target, step, status, detail, incident_id, approver):
        self.writes.append({"sg_id": target.sg_id, "step": step, "status": status,
                            "detail": detail, "incident_id": incident_id, "approver": approver})
        return {"row_uid": f"row-{len(self.writes)}",
                "s3_evidence_uri": f"s3://bucket/{target.sg_id}-{len(self.writes)}.json"}


@dataclass
class _FakeEC2:
    sgs: dict[str, dict] = field(default_factory=dict)
    raise_on_describe: bool = False
    raise_on_revoke: bool = False
    revokes: list[tuple[str, list[str], list[int]]] = field(default_factory=list)

    def describe_security_group(self, sg_id):
        if self.raise_on_describe:
            raise RuntimeError("simulated ec2 502")
        return self.sgs.get(sg_id)

    def revoke_security_group_ingress(self, sg_id, *, cidrs, ports):
        if self.raise_on_revoke:
            raise RuntimeError("simulated ec2 403")
        self.revokes.append((sg_id, list(cidrs), list(ports)))
        # Update the in-memory SG to reflect the revoke
        sg = self.sgs.setdefault(sg_id, {"GroupId": sg_id, "GroupName": "x", "IpPermissions": [], "Tags": []})
        keep = []
        for perm in sg.get("IpPermissions") or []:
            from_p, to_p = perm.get("FromPort"), perm.get("ToPort")
            try:
                lo, hi = int(from_p), int(to_p)
            except (TypeError, ValueError):
                lo = hi = None
            if lo is not None and hi is not None and any(lo <= p <= hi for p in ports):
                # Drop cidrs that match
                new_v4 = [r for r in perm.get("IpRanges") or []
                          if (r or {}).get("CidrIp") not in cidrs]
                new_v6 = [r for r in perm.get("Ipv6Ranges") or []
                          if (r or {}).get("CidrIpv6") not in cidrs]
                if new_v4 or new_v6:
                    perm["IpRanges"] = new_v4
                    perm["Ipv6Ranges"] = new_v6
                    keep.append(perm)
                # else: permission emptied, drop entirely
            else:
                keep.append(perm)
        sg["IpPermissions"] = keep


# ---------- contract ----------


def test_accepted_producers_set():
    assert ACCEPTED_PRODUCERS == frozenset({"detect-aws-open-security-group"})


def test_default_protected_name_prefixes_cover_default_sg():
    assert "default" in DEFAULT_PROTECTED_SG_NAME_PREFIXES


def test_intentionally_open_tag_default():
    assert DEFAULT_INTENTIONALLY_OPEN_TAG == "intentionally-open"


def test_check_apply_gate_requires_both_envs(monkeypatch):
    monkeypatch.delenv("AWS_SG_REVOKE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("AWS_SG_REVOKE_APPROVER", raising=False)
    ok, _ = check_apply_gate()
    assert ok is False
    monkeypatch.setenv("AWS_SG_REVOKE_INCIDENT_ID", "INC-1")
    ok, _ = check_apply_gate()
    assert ok is False
    monkeypatch.setenv("AWS_SG_REVOKE_APPROVER", "alice")
    ok, _ = check_apply_gate()
    assert ok is True


# ---------- parse_targets ----------


def test_parse_targets_extracts_full_target():
    target, _ = next(parse_targets([_finding(cidrs=["0.0.0.0/0", "::/0"], ports=[22, 3306])]))
    assert target.sg_id == "sg-rogue"
    assert target.cidrs == ("0.0.0.0/0", "::/0")
    assert target.ports == (22, 3306)
    assert target.account_uid == "111122223333"


def test_parse_targets_rejects_wrong_producer(capsys):
    e = _finding()
    e["metadata"]["product"]["feature"]["name"] = "detect-okta-mfa-fatigue"
    target, _ = next(parse_targets([e]))
    assert target is None
    assert "unaccepted producer" in capsys.readouterr().err


# ---------- protected check ----------


def _t(**overrides) -> Target:
    base = dict(sg_id="sg-x", sg_name="x", region="us-east-1", account_uid="1",
                cidrs=("0.0.0.0/0",), ports=(22,), actor="a", rule="r",
                producer_skill="detect-aws-open-security-group", finding_uid="f")
    base.update(overrides)
    return Target(**base)


def test_protected_default_sg_by_name():
    p, why = is_protected_sg(_t(sg_name="default"), name_prefixes=("default",), sg_ids=(),
                              intentionally_open_tag="intentionally-open", sg_describe=None)
    assert p is True
    assert "default" in why


def test_protected_via_env_id_allowlist():
    p, why = is_protected_sg(_t(sg_id="sg-allow"), name_prefixes=(), sg_ids=("sg-allow",),
                              intentionally_open_tag="intentionally-open", sg_describe=None)
    assert p is True
    assert "sg-allow" in why


def test_protected_via_intentionally_open_tag():
    sg = {"Tags": [{"Key": "intentionally-open", "Value": "alb-443"}]}
    p, why = is_protected_sg(_t(), name_prefixes=(), sg_ids=(),
                              intentionally_open_tag="intentionally-open", sg_describe=sg)
    assert p is True
    assert "intentionally-open" in why


def test_unprotected_when_no_match():
    p, _ = is_protected_sg(_t(sg_name="my-prod-sg"), name_prefixes=("default",), sg_ids=(),
                           intentionally_open_tag="intentionally-open", sg_describe={"Tags": []})
    assert p is False


# ---------- run: dry-run ----------


def test_run_dry_run_emits_plan():
    records = list(run([_finding()], ec2_client=_FakeEC2()))
    rec = records[0]
    assert rec["record_type"] == "remediation_plan"
    assert rec["status"] == STATUS_PLANNED
    assert rec["dry_run"] is True
    assert rec["target"]["sg_id"] == "sg-rogue"
    assert rec["target"]["cidrs"] == ["0.0.0.0/0"]
    assert rec["target"]["ports"] == [22]


def test_run_dry_run_does_not_call_revoke():
    ec2 = _FakeEC2()
    list(run([_finding()], ec2_client=ec2))
    assert ec2.revokes == []


# ---------- run: skip paths ----------


def test_run_skips_finding_without_sg_id():
    records = list(run([_finding(omit_sg_id=True)], ec2_client=_FakeEC2()))
    assert records[0]["status"] == STATUS_SKIPPED_NO_SG


def test_run_skips_default_sg_in_dry_run():
    records = list(run([_finding(sg_id="sg-default-vpc", sg_name="default")],
                       ec2_client=_FakeEC2()))
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED
    assert "default" in records[0]["status_detail"]


def test_run_skips_intentionally_open_tagged_sg_in_apply():
    audit = _FakeAudit()
    ec2 = _FakeEC2(sgs={"sg-rogue": {"GroupId": "sg-rogue", "Tags": [{"Key": "intentionally-open", "Value": "yes"}], "IpPermissions": []}})
    records = list(run([_finding()], ec2_client=ec2, apply=True, audit=audit,
                       incident_id="INC-1", approver="alice"))
    assert records[0]["status"] == STATUS_SKIPPED_PROTECTED
    assert ec2.revokes == []
    assert audit.writes == []


def test_run_skips_via_env_protected_id():
    records = list(run([_finding(sg_id="sg-bootstrap")], ec2_client=_FakeEC2(),
                       sg_ids=("sg-bootstrap",)))
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED


# ---------- run: apply ----------


def test_run_apply_revokes_with_dual_audit():
    audit = _FakeAudit()
    ec2 = _FakeEC2(sgs={"sg-rogue": {"GroupId": "sg-rogue", "Tags": [],
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}})
    records = list(run([_finding()], ec2_client=ec2, apply=True, audit=audit,
                       incident_id="INC-1", approver="alice@security"))
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert rec["dry_run"] is False
    assert ec2.revokes == [("sg-rogue", ["0.0.0.0/0"], [22])]
    assert len(audit.writes) == 2
    assert audit.writes[0]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[1]["status"] == STATUS_SUCCESS


def test_run_apply_writes_failure_audit_when_revoke_throws():
    audit = _FakeAudit()
    ec2 = _FakeEC2(raise_on_revoke=True)
    records = list(run([_finding()], ec2_client=ec2, apply=True, audit=audit,
                       incident_id="INC-1", approver="alice"))
    assert records[0]["status"] == STATUS_FAILURE
    assert len(audit.writes) == 2
    assert audit.writes[1]["status"] == STATUS_FAILURE


def test_run_apply_requires_audit_writer():
    import pytest
    with pytest.raises(ValueError, match="audit writer is required"):
        list(run([_finding()], ec2_client=_FakeEC2(), apply=True, audit=None))


# ---------- run: re-verify ----------


def test_run_reverify_verified_when_offending_perm_gone():
    ec2 = _FakeEC2(sgs={"sg-rogue": {"GroupId": "sg-rogue", "Tags": [], "IpPermissions": []}})
    records = list(run([_finding()], ec2_client=ec2, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"


def test_run_reverify_verified_when_sg_deleted():
    """Absent SG = stronger than revoked = verified containment."""
    ec2 = _FakeEC2(sgs={})
    records = list(run([_finding()], ec2_client=ec2, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"
    assert "not found" in records[0]["actual_state"]


def test_run_reverify_drift_emits_ocsf_finding_alongside_verification():
    ec2 = _FakeEC2(sgs={"sg-rogue": {"GroupId": "sg-rogue", "Tags": [],
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}})
    records = list(run([_finding()], ec2_client=ec2, reverify=True))
    assert len(records) == 2
    verification, finding = records
    assert verification["status"] == "drift"
    assert finding["class_uid"] == 2004
    assert finding["category_uid"] == 2
    assert finding["severity_id"] == 4
    assert finding["finding_info"]["types"] == ["remediation-drift"]
    assert any(
        obs["name"] == "remediation.skill" and obs["value"] == "remediate-aws-sg-revoke"
        for obs in finding["observables"]
    )


def test_run_reverify_unreachable_never_silently_downgrades():
    ec2 = _FakeEC2(raise_on_describe=True)
    records = list(run([_finding()], ec2_client=ec2, reverify=True))
    # Note: run() also calls describe at the protected-check stage. With
    # raise_on_describe, that returns None (caught); the protected-check
    # passes (no tags visible), then reverify_target's own describe call
    # raises and produces UNREACHABLE.
    # So we get either a single UNREACHABLE record OR a passing-through
    # PROTECTED check followed by UNREACHABLE.
    assert any(r["status"] == "unreachable" for r in records)
