"""Tests for detect-lateral-movement."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    API_ACTIVITY_CLASS,
    ASSUME_ROLE_OPERATIONS,
    CORRELATION_WINDOW_MS,
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    GCP_IDENTITY_PIVOT_SUFFIXES,
    MIN_BYTES,
    NET_ACTIVITY_ACCEPT,
    NETWORK_ACTIVITY_CLASS,
    SEVERITY_HIGH,
    SKILL_NAME,
    T1021_TECH_UID,
    T1078_SUB_UID,
    T1078_TECH_UID,
    detect,
    is_identity_pivot_anchor,
    is_rfc1918,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT = GOLDEN / "lateral_movement_input.ocsf.jsonl"
EXPECTED = GOLDEN / "lateral_movement_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _anchor_event(
    *,
    provider: str = "AWS",
    service: str = "sts.amazonaws.com",
    operation: str = "AssumeRole",
    account: str = "111122223333",
    session_uid: str = "ASIASESSION001",
    time_ms: int = 1775797200000,
    actor: str = "alice",
) -> dict:
    return {
        "class_uid": API_ACTIVITY_CLASS,
        "activity_id": 99,
        "time": time_ms,
        "actor": {"user": {"name": actor, "type": "IAMUser"}, "session": {"uid": session_uid}},
        "api": {"operation": operation, "service": {"name": service}},
        "cloud": {"provider": provider, "account": {"uid": account}},
    }


def _flow(
    *,
    provider: str = "AWS",
    account: str = "111122223333",
    src_ip: str = "10.0.1.100",
    dst_ip: str = "10.0.3.75",
    dst_port: int = 3306,
    bytes_: int = 450000,
    activity_id: int = NET_ACTIVITY_ACCEPT,
    time_ms: int = 1775797320000,
    instance: str = "i-0web01",
) -> dict:
    return {
        "class_uid": NETWORK_ACTIVITY_CLASS,
        "activity_id": activity_id,
        "time": time_ms,
        "src_endpoint": {"ip": src_ip, "port": 55412, "instance_uid": instance, "subnet_uid": "subnet-priv-1a"},
        "dst_endpoint": {"ip": dst_ip, "port": dst_port},
        "traffic": {"packets": 300, "bytes": bytes_},
        "connection_info": {"protocol_num": 6, "protocol_name": "TCP"},
        "cloud": {"provider": provider, "account": {"uid": account}},
    }


# ── RFC1918 helper ───────────────────────────────────────────────


class TestIsRfc1918:
    def test_10_8(self):
        assert is_rfc1918("10.0.0.1")
        assert is_rfc1918("10.255.255.255")

    def test_172_16(self):
        assert is_rfc1918("172.16.0.1")
        assert is_rfc1918("172.31.255.255")
        assert not is_rfc1918("172.32.0.1")  # outside /12

    def test_192_168(self):
        assert is_rfc1918("192.168.0.1")
        assert is_rfc1918("192.168.255.255")

    def test_cgnat(self):
        # 100.64.0.0/10 — shared address space, included because EKS/GKE use it
        assert is_rfc1918("100.64.0.1")
        assert is_rfc1918("100.127.255.255")

    def test_public_addresses(self):
        for ip in ("8.8.8.8", "1.1.1.1", "104.18.32.7", "203.0.113.42", "52.94.10.20"):
            assert not is_rfc1918(ip), f"{ip} should not be RFC1918"

    def test_empty(self):
        assert not is_rfc1918("")

    def test_garbage(self):
        assert not is_rfc1918("not-an-ip")


# ── Positive cases ───────────────────────────────────────────────


class TestPositiveCases:
    def test_assume_role_plus_internal_flow_fires(self):
        events = [
            _anchor_event(time_ms=1000),
            _flow(time_ms=60000, dst_ip="10.0.3.75", bytes_=450000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID == 2004
        assert f["category_uid"] == FINDING_CATEGORY_UID == 2
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_HIGH
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert f["observables"][0]["value"] == "AWS"

    def test_both_mitre_techniques_populated(self):
        events = [_anchor_event(), _flow()]
        f = list(detect(events))[0]
        attacks = f["finding_info"]["attacks"]
        assert len(attacks) == 2
        technique_uids = {a["technique"]["uid"] for a in attacks}
        assert T1021_TECH_UID in technique_uids
        assert T1078_TECH_UID in technique_uids
        sub_uids = {a.get("sub_technique", {}).get("uid") for a in attacks}
        assert T1078_SUB_UID in sub_uids

    def test_attacks_inside_finding_info_not_root(self):
        events = [_anchor_event(), _flow()]
        f = list(detect(events))[0]
        assert "attacks" not in f
        assert "attacks" in f["finding_info"]

    def test_multiple_internal_dsts_produce_multiple_findings(self):
        events = [
            _anchor_event(time_ms=1000),
            _flow(time_ms=60000, dst_ip="10.0.3.75", dst_port=3306, bytes_=450000),
            _flow(time_ms=120000, dst_ip="10.0.2.50", dst_port=22, bytes_=8200),
        ]
        findings = list(detect(events))
        assert len(findings) == 2
        dsts = {tuple(o["value"] for o in f["observables"] if o["name"] in ("dst.ip", "dst.port")) for f in findings}
        assert ("10.0.3.75", "3306") in dsts or ("10.0.3.75", "3306") in {(d[0], d[1]) for d in dsts if len(d) >= 2}

    def test_deterministic_uid(self):
        events = [_anchor_event(), _flow()]
        a = list(detect(events))[0]["finding_info"]["uid"]
        b = list(detect(events))[0]["finding_info"]["uid"]
        assert a == b
        assert a.startswith("det-lm-")

    def test_dedupe_same_session_same_dst(self):
        # Two flows from same session to same dst → one finding
        events = [
            _anchor_event(time_ms=1000),
            _flow(time_ms=60000, dst_ip="10.0.3.75", dst_port=3306, bytes_=450000),
            _flow(time_ms=120000, dst_ip="10.0.3.75", dst_port=3306, bytes_=300000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1


# ── Negative controls ───────────────────────────────────────────


class TestNegativeControls:
    def test_assume_role_without_flow(self):
        assert list(detect([_anchor_event()])) == []

    def test_flow_without_assume_role(self):
        assert list(detect([_flow()])) == []

    def test_flow_to_public_ip_filtered(self):
        events = [
            _anchor_event(time_ms=1000),
            _flow(time_ms=60000, dst_ip="104.18.32.7", bytes_=125000),
        ]
        assert list(detect(events)) == []

    def test_flow_under_byte_threshold_filtered(self):
        events = [
            _anchor_event(time_ms=1000),
            _flow(time_ms=60000, dst_ip="10.0.3.75", bytes_=MIN_BYTES - 1),
        ]
        assert list(detect(events)) == []

    def test_reject_flow_not_counted(self):
        events = [
            _anchor_event(time_ms=1000),
            _flow(time_ms=60000, dst_ip="10.0.3.75", bytes_=450000, activity_id=7),  # REJECT
        ]
        assert list(detect(events)) == []

    def test_flow_outside_window_filtered(self):
        events = [
            _anchor_event(time_ms=1000),
            _flow(time_ms=1000 + CORRELATION_WINDOW_MS + 1, dst_ip="10.0.3.75", bytes_=450000),
        ]
        assert list(detect(events)) == []

    def test_flow_before_assume_role_filtered(self):
        events = [
            _anchor_event(time_ms=1000000),
            _flow(time_ms=500000, dst_ip="10.0.3.75", bytes_=450000),
        ]
        assert list(detect(events)) == []

    def test_non_assume_role_api_ignored(self):
        api_event = {
            "class_uid": API_ACTIVITY_CLASS,
            "activity_id": 2,
            "time": 1000,
            "actor": {"user": {"name": "alice"}, "session": {"uid": "S1"}},
            "api": {"operation": "ListBuckets"},
        }
        events = [api_event, _flow(time_ms=60000)]
        assert list(detect(events)) == []


# ── ASSUME_ROLE_OPERATIONS coverage ─────────────────────────────


class TestAssumeRoleVariants:
    def test_assume_role_fires(self):
        events = [_anchor_event(), _flow()]
        assert len(list(detect(events))) == 1

    def test_assume_role_with_saml_fires(self):
        ar = _anchor_event()
        ar["api"]["operation"] = "AssumeRoleWithSAML"
        assert len(list(detect([ar, _flow()]))) == 1

    def test_assume_role_with_web_identity_fires(self):
        ar = _anchor_event()
        ar["api"]["operation"] = "AssumeRoleWithWebIdentity"
        assert len(list(detect([ar, _flow()]))) == 1

    def test_assume_role_operations_constant(self):
        assert "AssumeRole" in ASSUME_ROLE_OPERATIONS
        assert "AssumeRoleWithSAML" in ASSUME_ROLE_OPERATIONS
        assert "AssumeRoleWithWebIdentity" in ASSUME_ROLE_OPERATIONS


class TestCrossCloudAnchors:
    def test_gcp_identity_pivot_fires(self):
        anchor = _anchor_event(
            provider="GCP",
            service="iamcredentials.googleapis.com",
            operation="google.iam.credentials.v1.GenerateAccessToken",
            account="my-project",
            session_uid="gcp-session-1",
        )
        flow = _flow(provider="GCP", account="my-project", dst_ip="10.128.0.8")
        findings = list(detect([anchor, flow]))
        assert len(findings) == 1
        assert findings[0]["observables"][0]["value"] == "GCP"

    def test_azure_identity_pivot_fires(self):
        anchor = _anchor_event(
            provider="Azure",
            service="microsoft.authorization",
            operation="MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
            account="00000000-0000-0000-0000-000000000000",
            session_uid="azure-session-1",
        )
        flow = _flow(
            provider="Azure",
            account="00000000-0000-0000-0000-000000000000",
            dst_ip="10.1.2.7",
        )
        findings = list(detect([anchor, flow]))
        assert len(findings) == 1
        assert findings[0]["observables"][0]["value"] == "Azure"

    def test_provider_mismatch_does_not_fire(self):
        anchor = _anchor_event(provider="AWS", session_uid="aws-session-1")
        flow = _flow(provider="GCP", account="my-project", dst_ip="10.128.0.8")
        assert list(detect([anchor, flow])) == []

    def test_account_mismatch_does_not_fire(self):
        anchor = _anchor_event(provider="Azure", account="sub-a", session_uid="azure-session-1")
        flow = _flow(provider="Azure", account="sub-b", dst_ip="10.1.2.7")
        assert list(detect([anchor, flow])) == []

    def test_gcp_anchor_suffixes_constant(self):
        assert "GenerateAccessToken" in GCP_IDENTITY_PIVOT_SUFFIXES
        assert "CreateServiceAccountKey" in GCP_IDENTITY_PIVOT_SUFFIXES

    def test_anchor_classifier(self):
        assert is_identity_pivot_anchor(_anchor_event())
        assert is_identity_pivot_anchor(
            _anchor_event(
                provider="GCP",
                service="iamcredentials.googleapis.com",
                operation="google.iam.credentials.v1.SignJwt",
            )
        )
        assert is_identity_pivot_anchor(
            _anchor_event(
                provider="Azure",
                service="microsoft.authorization",
                operation="MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
            )
        )


# ── Stream robustness ───────────────────────────────────────────


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err


# ── Golden fixture parity ───────────────────────────────────────


class TestGoldenFixture:
    def test_exactly_two_findings(self):
        events = _load(INPUT)
        findings = list(detect(events))
        assert len(findings) == 2

    def test_deep_eq_against_frozen_golden(self):
        events = _load(INPUT)
        produced = list(detect(events))
        expected = _load(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e

    def test_fixture_fires_on_mysql_target(self):
        events = _load(INPUT)
        findings = list(detect(events))
        dst_ips = set()
        for f in findings:
            obs = {o["name"]: o["value"] for o in f["observables"]}
            dst_ips.add(f"{obs['dst.ip']}:{obs['dst.port']}")
        assert "10.0.3.75:3306" in dst_ips

    def test_fixture_does_not_fire_on_public_egress(self):
        events = _load(INPUT)
        findings = list(detect(events))
        for f in findings:
            obs = {o["name"]: o["value"] for o in f["observables"]}
            assert obs["dst.ip"] != "104.18.32.7"

    def test_fixture_does_not_fire_on_out_of_window(self):
        events = _load(INPUT)
        findings = list(detect(events))
        for f in findings:
            obs = {o["name"]: o["value"] for o in f["observables"]}
            assert obs["dst.ip"] != "10.0.4.99"
