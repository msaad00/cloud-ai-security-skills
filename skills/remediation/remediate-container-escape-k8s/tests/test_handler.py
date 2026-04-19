"""Tests for remediate-container-escape-k8s."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    DEFAULT_DENY_NAMESPACES,
    STATUS_DRIFT,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_DENY_LIST,
    STATUS_SUCCESS,
    STATUS_VERIFIED,
    STATUS_WOULD_VIOLATE_DENY_LIST,
    check_apply_gate,
    is_protected_namespace,
    parse_targets,
    run,
)


def _finding(
    *,
    producer: str = "detect-container-escape-k8s",
    target: str = "deployments/payments/api",
    namespace: str = "payments",
    resource_type: str = "deployments",
    resource_name: str = "api",
    pod_name: str = "",
    finding_uid: str = "find-1",
) -> dict:
    observables = [
        {"name": "namespace", "type": "Other", "value": namespace},
        {"name": "resource.type", "type": "Other", "value": resource_type},
        {"name": "resource.name", "type": "Other", "value": resource_name},
    ]
    if pod_name:
        observables.append({"name": "pod.name", "type": "Other", "value": pod_name})
    return {
        "class_uid": 2004,
        "target": target,
        "metadata": {
            "uid": finding_uid,
            "product": {"feature": {"name": producer}},
        },
        "finding_info": {"uid": finding_uid},
        "observables": observables,
    }


@dataclass
class _FakeAudit:
    writes: list[dict] = field(default_factory=list)

    def record(self, *, target, step, status, detail, incident_id, approver, policy_name):
        entry = {
            "target": f"{target.namespace}/{target.resource_type}/{target.resource_name}",
            "step": step,
            "status": status,
            "detail": detail,
            "incident_id": incident_id,
            "approver": approver,
            "policy_name": policy_name,
        }
        self.writes.append(entry)
        return {
            "row_uid": f"row-{len(self.writes)}",
            "s3_evidence_uri": f"s3://bucket/{policy_name}-{len(self.writes)}.json",
        }


@dataclass
class _FakeKube:
    pod_labels: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)
    workload_selectors: dict[tuple[str, str, str], dict[str, str]] = field(default_factory=dict)
    policies: dict[tuple[str, str], dict] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    audit: _FakeAudit | None = None

    def get_pod_labels(self, namespace: str, pod_name: str):
        return self.pod_labels.get((namespace, pod_name))

    def get_workload_selector(self, namespace: str, resource_type: str, resource_name: str):
        return self.workload_selectors.get((namespace, resource_type, resource_name))

    def apply_network_policy(self, namespace: str, manifest: dict):
        if self.audit is not None:
            assert self.audit.writes, "audit must precede the Kubernetes write"
            assert self.audit.writes[0]["status"] == STATUS_IN_PROGRESS
        self.order.append("kube:apply")
        name = manifest["metadata"]["name"]
        self.policies[(namespace, name)] = manifest

    def get_network_policy(self, namespace: str, name: str):
        return self.policies.get((namespace, name))


class TestContract:
    def test_accepted_producer_is_container_escape_detector(self):
        assert ACCEPTED_PRODUCERS == frozenset({"detect-container-escape-k8s"})

    def test_default_deny_namespaces_cover_system_planes(self):
        assert "kube-system" in DEFAULT_DENY_NAMESPACES
        assert "istio-system" in DEFAULT_DENY_NAMESPACES
        assert "linkerd-" in DEFAULT_DENY_NAMESPACES


class TestParseTargets:
    def test_parses_workload_target_from_ocsf_finding(self):
        results = list(parse_targets([_finding()]))
        assert len(results) == 1
        target, _ = results[0]
        assert target is not None
        assert target.namespace == "payments"
        assert target.resource_type == "deployments"
        assert target.resource_name == "api"
        assert target.producer_skill == "detect-container-escape-k8s"

    def test_parses_pod_target_for_ephemeral_container_finding(self):
        target, _ = next(
            parse_targets(
                [
                    _finding(
                        target="pods/payments/api-7d9b/ephemeralcontainers",
                        resource_type="pods",
                        resource_name="api-7d9b",
                        pod_name="api-7d9b",
                    )
                ]
            )
        )
        assert target is not None
        assert target.pod_name == "api-7d9b"
        assert target.resource_type == "pods"
        assert target.resource_name == "api-7d9b"

    def test_refuses_non_container_escape_producer(self, capsys):
        results = list(parse_targets([_finding(producer="detect-privilege-escalation-k8s")]))
        assert len(results) == 1
        target, _ = results[0]
        assert target is None
        assert "unaccepted producer" in capsys.readouterr().err


class TestDenyList:
    def test_linkerd_namespace_is_protected(self):
        denied, matched = is_protected_namespace("linkerd-viz", DEFAULT_DENY_NAMESPACES)
        assert denied is True
        assert matched == "linkerd-"

    def test_dry_run_returns_would_violate_for_protected_namespace(self):
        kube = _FakeKube()
        records = list(
            run(
                [_finding(namespace="kube-system", target="deployments/kube-system/coredns", resource_name="coredns")],
                kube_client=kube,
            )
        )
        assert len(records) == 1
        assert records[0]["status"] == STATUS_WOULD_VIOLATE_DENY_LIST
        assert records[0]["dry_run"] is True

    def test_apply_skips_protected_namespace_without_writing(self):
        kube = _FakeKube()
        audit = _FakeAudit()
        records = list(
            run(
                [_finding(namespace="istio-system", target="deployments/istio-system/istiod", resource_name="istiod")],
                kube_client=kube,
                apply=True,
                audit=audit,
                incident_id="inc-1",
                approver="alice@example.com",
            )
        )
        assert len(records) == 1
        assert records[0]["status"] == STATUS_SKIPPED_DENY_LIST
        assert audit.writes == []
        assert kube.order == []


class TestDryRunDefault:
    def test_dry_run_emits_plan_with_selector_and_manifest(self):
        kube = _FakeKube(workload_selectors={("payments", "deployments", "api"): {"app": "api"}})
        records = list(run([_finding()], kube_client=kube))
        assert len(records) == 1
        record = records[0]
        assert record["record_type"] == "remediation_plan"
        assert record["status"] == STATUS_PLANNED
        assert record["dry_run"] is True
        assert record["selector"] == {"app": "api"}
        assert record["manifest"]["kind"] == "NetworkPolicy"
        assert record["manifest"]["spec"]["ingress"] == []
        assert record["manifest"]["spec"]["egress"] == []


class TestApplyGate:
    def test_apply_requires_incident_id_and_approver(self, monkeypatch):
        monkeypatch.delenv("K8S_CONTAINER_ESCAPE_INCIDENT_ID", raising=False)
        monkeypatch.delenv("K8S_CONTAINER_ESCAPE_APPROVER", raising=False)
        ok, reason = check_apply_gate()
        assert ok is False
        assert "INCIDENT_ID" in reason

        monkeypatch.setenv("K8S_CONTAINER_ESCAPE_INCIDENT_ID", "inc-1")
        ok, reason = check_apply_gate()
        assert ok is False
        assert "APPROVER" in reason

        monkeypatch.setenv("K8S_CONTAINER_ESCAPE_APPROVER", "alice@example.com")
        ok, reason = check_apply_gate()
        assert ok is True
        assert reason == ""


class TestApplyAndReverify:
    def test_apply_writes_audit_before_network_policy(self):
        audit = _FakeAudit()
        kube = _FakeKube(
            workload_selectors={("payments", "deployments", "api"): {"app": "api"}},
            audit=audit,
        )
        records = list(
            run(
                [_finding()],
                kube_client=kube,
                apply=True,
                audit=audit,
                incident_id="inc-1",
                approver="alice@example.com",
            )
        )
        assert len(records) == 1
        record = records[0]
        assert record["record_type"] == "remediation_action"
        assert record["status"] == STATUS_SUCCESS
        assert record["incident_id"] == "inc-1"
        assert record["approver"] == "alice@example.com"
        assert [item["status"] for item in audit.writes] == [STATUS_IN_PROGRESS, STATUS_SUCCESS]
        assert kube.order == ["kube:apply"]

    def test_reverify_reports_verified_when_policy_matches(self):
        kube = _FakeKube(
            workload_selectors={("payments", "deployments", "api"): {"app": "api"}}
        )
        plan = next(run([_finding()], kube_client=kube))
        kube.policies[("payments", plan["policy_name"])] = plan["manifest"]
        record = next(run([_finding()], kube_client=kube, reverify=True))
        assert record["record_type"] == "remediation_verification"
        assert record["status"] == STATUS_VERIFIED

    def test_reverify_reports_drift_when_policy_selector_changes(self):
        kube = _FakeKube(
            workload_selectors={("payments", "deployments", "api"): {"app": "api"}}
        )
        plan = next(run([_finding()], kube_client=kube))
        drifted = dict(plan["manifest"])
        drifted["spec"] = dict(plan["manifest"]["spec"])
        drifted["spec"]["podSelector"] = {"matchLabels": {"app": "api", "tier": "wrong"}}
        kube.policies[("payments", plan["policy_name"])] = drifted
        record = next(run([_finding()], kube_client=kube, reverify=True))
        assert record["status"] == STATUS_DRIFT

    def test_reverify_emits_ocsf_drift_finding_alongside_verification_record(self):
        """DRIFT outcome must emit BOTH a remediation_verification record
        AND an OCSF Detection Finding (class_uid 2004) so the drift flows
        through the same SIEM/SOAR pipeline as every other finding."""
        kube = _FakeKube(
            workload_selectors={("payments", "deployments", "api"): {"app": "api"}}
        )
        # Quarantine policy is missing entirely → DRIFT
        records = list(run([_finding()], kube_client=kube, reverify=True))
        assert len(records) == 2
        verification, finding = records
        assert verification["record_type"] == "remediation_verification"
        assert verification["status"] == STATUS_DRIFT
        # OCSF Detection Finding shape
        assert finding["class_uid"] == 2004
        assert finding["category_uid"] == 2
        assert finding["severity_id"] == 4  # SEVERITY_HIGH
        assert finding["finding_info"]["types"] == ["remediation-drift"]
        assert any(
            obs["name"] == "remediation.skill" and obs["value"] == "remediate-container-escape-k8s"
            for obs in finding["observables"]
        )
        # The drift finding must reference the original finding so SIEM can correlate
        assert any(
            obs["name"] == "original.finding_uid" and obs["value"] == "find-1"
            for obs in finding["observables"]
        )

    def test_reverify_verified_path_does_not_emit_drift_finding(self):
        kube = _FakeKube(
            workload_selectors={("payments", "deployments", "api"): {"app": "api"}}
        )
        plan = next(run([_finding()], kube_client=kube))
        kube.policies[("payments", plan["policy_name"])] = plan["manifest"]
        records = list(run([_finding()], kube_client=kube, reverify=True))
        assert len(records) == 1
        assert records[0]["status"] == STATUS_VERIFIED
