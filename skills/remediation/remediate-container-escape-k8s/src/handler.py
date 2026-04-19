"""Contain a Kubernetes container-escape signal with a deny-all NetworkPolicy.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
detect-container-escape-k8s. Plans (dry-run default), applies (--apply), or
re-verifies (--reverify) a namespace-scoped deny-all NetworkPolicy that
matches the target pod or workload selector.

Guardrails enforced in code:
- source-skill check rejects findings from any non-container-escape producer
- deny-list of protected namespaces (kube-system, kube-public, istio-system, linkerd*)
- --apply requires K8S_CONTAINER_ESCAPE_INCIDENT_ID + K8S_CONTAINER_ESCAPE_APPROVER
- dual-audit write (DynamoDB + S3) BEFORE and AFTER the NetworkPolicy write
- --reverify checks that the policy still exists and still matches the selector
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "remediate-container-escape-k8s"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset({"detect-container-escape-k8s"})

DEFAULT_DENY_NAMESPACES = (
    "kube-system",
    "kube-public",
    "istio-system",
    "linkerd",
    "linkerd-",
)

SUPPORTED_WORKLOAD_TYPES = frozenset(
    {
        "pods",
        "deployments",
        "daemonsets",
        "statefulsets",
        "replicasets",
        "replicationcontrollers",
        "jobs",
        "cronjobs",
    }
)

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_APPLY_QUARANTINE = "apply_quarantine_network_policy"

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_DENY_LIST = "skipped_deny_list"
STATUS_WOULD_VIOLATE_DENY_LIST = "would-violate-deny-list"
STATUS_SKIPPED_UNSUPPORTED_TARGET = "skipped_unsupported_target"


@dataclasses.dataclass(frozen=True)
class Target:
    namespace: str
    resource_type: str
    resource_name: str
    pod_name: str
    producer_skill: str
    finding_uid: str


@dataclasses.dataclass(frozen=True)
class ResolvedTarget:
    target: Target
    selector: dict[str, str]
    policy_name: str
    manifest: dict[str, Any]


class KubernetesClient(Protocol):
    def get_pod_labels(self, namespace: str, pod_name: str) -> dict[str, str] | None: ...
    def get_workload_selector(self, namespace: str, resource_type: str, resource_name: str) -> dict[str, str] | None: ...
    def apply_network_policy(self, namespace: str, manifest: dict[str, Any]) -> None: ...
    def get_network_policy(self, namespace: str, name: str) -> dict[str, Any] | None: ...


class AuditWriter(Protocol):
    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
        policy_name: str,
    ) -> dict[str, str]: ...


@dataclasses.dataclass
class KubernetesApiClient:
    """Real Kubernetes client. Imported lazily so tests can use stubs."""

    def _apis(self) -> tuple[Any, Any, Any, Any]:
        from kubernetes import client  # local import
        from kubernetes.config import load_incluster_config, load_kube_config

        try:
            load_incluster_config()
        except Exception:
            load_kube_config()
        return (
            client.CoreV1Api(),
            client.AppsV1Api(),
            client.BatchV1Api(),
            client.NetworkingV1Api(),
        )

    def get_pod_labels(self, namespace: str, pod_name: str) -> dict[str, str] | None:
        core, _, _, _ = self._apis()
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
        labels = (getattr(pod.metadata, "labels", None) or {}) if getattr(pod, "metadata", None) else {}
        return dict(labels) if labels else None

    def get_workload_selector(self, namespace: str, resource_type: str, resource_name: str) -> dict[str, str] | None:
        _, apps, batch, _ = self._apis()

        def _selector(obj: Any) -> dict[str, str] | None:
            spec = getattr(obj, "spec", None)
            if spec is None:
                return None
            selector = getattr(spec, "selector", None)
            labels = getattr(selector, "match_labels", None) if selector is not None else None
            if labels:
                return dict(labels)
            template = getattr(spec, "template", None)
            metadata = getattr(template, "metadata", None) if template is not None else None
            tmpl_labels = getattr(metadata, "labels", None) if metadata is not None else None
            return dict(tmpl_labels) if tmpl_labels else None

        if resource_type == "deployments":
            return _selector(apps.read_namespaced_deployment(name=resource_name, namespace=namespace))
        if resource_type == "daemonsets":
            return _selector(apps.read_namespaced_daemon_set(name=resource_name, namespace=namespace))
        if resource_type == "statefulsets":
            return _selector(apps.read_namespaced_stateful_set(name=resource_name, namespace=namespace))
        if resource_type == "replicasets":
            return _selector(apps.read_namespaced_replica_set(name=resource_name, namespace=namespace))
        if resource_type == "replicationcontrollers":
            core, _, _, _ = self._apis()
            rc = core.read_namespaced_replication_controller(name=resource_name, namespace=namespace)
            return _selector(rc)
        if resource_type == "jobs":
            return _selector(batch.read_namespaced_job(name=resource_name, namespace=namespace))
        if resource_type == "cronjobs":
            return _selector(batch.read_namespaced_cron_job(name=resource_name, namespace=namespace))
        return None

    def apply_network_policy(self, namespace: str, manifest: dict[str, Any]) -> None:
        _, _, _, net = self._apis()
        name = str((manifest.get("metadata") or {}).get("name") or "")
        try:
            net.read_namespaced_network_policy(name=name, namespace=namespace)
        except Exception:
            net.create_namespaced_network_policy(namespace=namespace, body=manifest)
            return
        net.replace_namespaced_network_policy(name=name, namespace=namespace, body=manifest)

    def get_network_policy(self, namespace: str, name: str) -> dict[str, Any] | None:
        _, _, _, net = self._apis()
        try:
            policy = net.read_namespaced_network_policy(name=name, namespace=namespace)
        except Exception:
            return None
        from kubernetes import client

        return client.ApiClient().sanitize_for_serialization(policy)


@dataclasses.dataclass
class DualAuditWriter:
    dynamodb_table: str
    s3_bucket: str
    kms_key_arn: str

    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
        policy_name: str,
    ) -> dict[str, str]:
        import boto3  # local import — tests inject a stub writer

        action_at = datetime.now(timezone.utc).isoformat()
        row_uid = _deterministic_uid(target.namespace, target.resource_type, target.resource_name, step, action_at)
        evidence_key = (
            "container-escape/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{target.namespace}/{target.resource_name}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "namespace": target.namespace,
            "resource_type": target.resource_type,
            "resource_name": target.resource_name,
            "pod_name": target.pod_name,
            "producer_skill": target.producer_skill,
            "finding_uid": target.finding_uid,
            "step": step,
            "status": status,
            "status_detail": detail,
            "incident_id": incident_id,
            "approver": approver,
            "policy_name": policy_name,
            "action_at": action_at,
        }
        body = json.dumps(envelope, separators=(",", ":"))

        boto3.client("s3").put_object(
            Bucket=self.s3_bucket,
            Key=evidence_key,
            Body=body.encode("utf-8"),
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms_key_arn,
            ContentType="application/json",
        )
        boto3.client("dynamodb").put_item(
            TableName=self.dynamodb_table,
            Item={
                "target_uid": {"S": f"{target.namespace}/{target.resource_type}/{target.resource_name}"},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "namespace": {"S": target.namespace},
                "resource_type": {"S": target.resource_type},
                "resource_name": {"S": target.resource_name},
                "policy_name": {"S": policy_name},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"rce-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _finding_product(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _finding_uid(event: dict[str, Any]) -> str:
    return str((event.get("finding_info") or {}).get("uid") or (event.get("metadata") or {}).get("uid") or "")


def _observable_value(event: dict[str, Any], name: str) -> str:
    for obs in event.get("observables") or []:
        if not isinstance(obs, dict):
            continue
        if obs.get("name") == name:
            return str(obs.get("value") or "")
    return ""


def _parse_target_string(value: str) -> tuple[str, str, str] | None:
    parts = [part for part in value.split("/") if part]
    if len(parts) < 3:
        return None
    resource_type = parts[0]
    namespace = parts[1]
    resource_name = parts[2]
    return resource_type, namespace, resource_name


def _target_from_event(event: dict[str, Any]) -> Target | None:
    producer = _finding_product(event)
    if producer not in ACCEPTED_PRODUCERS:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="wrong_source_skill",
            message=f"skipping finding from unaccepted producer `{producer or '<missing>'}`",
        )
        return None

    namespace = _observable_value(event, "namespace")
    pod_name = _observable_value(event, "pod.name")
    resource_type = _observable_value(event, "resource.type")
    resource_name = _observable_value(event, "resource.name")

    target_field = str(event.get("target") or "")
    parsed = _parse_target_string(target_field) if target_field else None
    if parsed:
        parsed_type, parsed_ns, parsed_name = parsed
        resource_type = resource_type or parsed_type
        namespace = namespace or parsed_ns
        resource_name = resource_name or parsed_name

    if pod_name:
        resource_type = resource_type or "pods"
        resource_name = resource_name or pod_name

    if not namespace or not resource_type or not resource_name:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="missing_target_context",
            message="skipping finding without enough namespace/resource context for quarantine planning",
        )
        return None

    return Target(
        namespace=namespace,
        resource_type=resource_type,
        resource_name=resource_name,
        pod_name=pod_name,
        producer_skill=producer,
        finding_uid=_finding_uid(event),
    )


def parse_targets(events: Iterable[dict[str, Any]]) -> Iterator[tuple[Target | None, dict[str, Any]]]:
    for event in events:
        yield _target_from_event(event), event


def load_deny_namespaces() -> tuple[str, ...]:
    return DEFAULT_DENY_NAMESPACES


def is_protected_namespace(namespace: str, patterns: Iterable[str]) -> tuple[bool, str]:
    value = (namespace or "").strip().lower()
    for pattern in patterns:
        needle = pattern.lower()
        if needle.endswith("-"):
            if value.startswith(needle):
                return True, pattern
        elif value == needle:
            return True, pattern
    return False, ""


def _policy_name(namespace: str, resource_type: str, resource_name: str, selector: dict[str, str]) -> str:
    material = json.dumps(selector, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(f"{namespace}|{resource_type}|{resource_name}|{material}".encode("utf-8")).hexdigest()[:10]
    base = resource_name.lower().replace("_", "-").replace(".", "-")
    base = "".join(ch for ch in base if ch.isalnum() or ch == "-").strip("-") or "target"
    return f"ce-quarantine-{base[:35]}-{digest}"[:63].rstrip("-")


def build_network_policy(namespace: str, policy_name: str, selector: dict[str, str]) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": policy_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": SKILL_NAME,
                "security.company.io/quarantine": "true",
            },
        },
        "spec": {
            "podSelector": {"matchLabels": selector},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }


def resolve_target(target: Target, kube_client: KubernetesClient) -> ResolvedTarget | None:
    selector: dict[str, str] | None
    if target.pod_name:
        selector = kube_client.get_pod_labels(target.namespace, target.pod_name)
    elif target.resource_type == "pods":
        selector = kube_client.get_pod_labels(target.namespace, target.resource_name)
    elif target.resource_type in SUPPORTED_WORKLOAD_TYPES:
        selector = kube_client.get_workload_selector(target.namespace, target.resource_type, target.resource_name)
    else:
        selector = None

    if not selector:
        return None

    policy_name = _policy_name(target.namespace, target.resource_type, target.resource_name, selector)
    return ResolvedTarget(
        target=target,
        selector=selector,
        policy_name=policy_name,
        manifest=build_network_policy(target.namespace, policy_name, selector),
    )


def check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("K8S_CONTAINER_ESCAPE_INCIDENT_ID", "").strip()
    approver = os.getenv("K8S_CONTAINER_ESCAPE_APPROVER", "").strip()
    if not incident_id:
        return False, "K8S_CONTAINER_ESCAPE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "K8S_CONTAINER_ESCAPE_APPROVER is required for --apply"
    return True, ""


def _policy_endpoint(namespace: str, name: str) -> str:
    return f"UPSERT /apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies/{name}"


def _verification_endpoint(namespace: str, name: str) -> str:
    return f"GET /apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies/{name}"


def _plan_record(resolved: ResolvedTarget, *, status: str, detail: str | None, dry_run: bool) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Kubernetes",
            "namespace": resolved.target.namespace,
            "resource_type": resolved.target.resource_type,
            "resource_name": resolved.target.resource_name,
            "pod_name": resolved.target.pod_name,
        },
        "policy_name": resolved.policy_name,
        "selector": resolved.selector,
        "manifest": resolved.manifest,
        "actions": [
            {
                "step": STEP_APPLY_QUARANTINE,
                "endpoint": _policy_endpoint(resolved.target.namespace, resolved.policy_name),
                "status": status,
                "detail": detail,
            }
        ],
        "status": status,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": resolved.target.finding_uid,
    }


def _skip_record(target: Target, *, status: str, detail: str, dry_run: bool) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Kubernetes",
            "namespace": target.namespace,
            "resource_type": target.resource_type,
            "resource_name": target.resource_name,
            "pod_name": target.pod_name,
        },
        "actions": [],
        "status": status,
        "status_detail": detail,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def _verification_record(resolved: ResolvedTarget, *, status: str, detail: str) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_VERIFICATION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Kubernetes",
            "namespace": resolved.target.namespace,
            "resource_type": resolved.target.resource_type,
            "resource_name": resolved.target.resource_name,
            "pod_name": resolved.target.pod_name,
        },
        "policy_name": resolved.policy_name,
        "selector": resolved.selector,
        "endpoint": _verification_endpoint(resolved.target.namespace, resolved.policy_name),
        "status": status,
        "status_detail": detail,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": resolved.target.finding_uid,
    }


def apply_quarantine(
    resolved: ResolvedTarget,
    *,
    kube_client: KubernetesClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
) -> dict[str, Any]:
    first_audit = audit.record(
        target=resolved.target,
        step=STEP_APPLY_QUARANTINE,
        status=STATUS_IN_PROGRESS,
        detail="about to apply quarantine NetworkPolicy",
        incident_id=incident_id,
        approver=approver,
        policy_name=resolved.policy_name,
    )
    try:
        kube_client.apply_network_policy(resolved.target.namespace, resolved.manifest)
    except Exception as exc:
        audit.record(
            target=resolved.target,
            step=STEP_APPLY_QUARANTINE,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
            policy_name=resolved.policy_name,
        )
        record = _plan_record(resolved, status=STATUS_FAILURE, detail=str(exc), dry_run=False)
        record["audit"] = first_audit
        return record

    second_audit = audit.record(
        target=resolved.target,
        step=STEP_APPLY_QUARANTINE,
        status=STATUS_SUCCESS,
        detail="quarantine NetworkPolicy applied",
        incident_id=incident_id,
        approver=approver,
        policy_name=resolved.policy_name,
    )
    record = _plan_record(resolved, status=STATUS_SUCCESS, detail="quarantine NetworkPolicy applied", dry_run=False)
    record["audit"] = second_audit
    record["incident_id"] = incident_id
    record["approver"] = approver
    return record


def reverify_quarantine(resolved: ResolvedTarget, *, kube_client: KubernetesClient) -> dict[str, Any]:
    policy = kube_client.get_network_policy(resolved.target.namespace, resolved.policy_name)
    if not policy:
        return _verification_record(resolved, status=STATUS_DRIFT, detail="quarantine NetworkPolicy not found")

    actual_selector = (((policy.get("spec") or {}).get("podSelector") or {}).get("matchLabels") or {})
    ingress = (policy.get("spec") or {}).get("ingress")
    egress = (policy.get("spec") or {}).get("egress")
    policy_types = tuple((policy.get("spec") or {}).get("policyTypes") or [])
    if actual_selector != resolved.selector or ingress != [] or egress != [] or set(policy_types) != {"Ingress", "Egress"}:
        return _verification_record(
            resolved,
            status=STATUS_DRIFT,
            detail="quarantine NetworkPolicy drifted from expected selector or deny-all shape",
        )
    return _verification_record(resolved, status=STATUS_VERIFIED, detail="quarantine NetworkPolicy still present")


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {exc}",
                line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object",
                line=lineno,
            )


def run(
    events: Iterable[dict[str, Any]],
    *,
    kube_client: KubernetesClient,
    apply: bool = False,
    reverify: bool = False,
    audit: AuditWriter | None = None,
    deny_namespaces: Iterable[str] = DEFAULT_DENY_NAMESPACES,
    incident_id: str = "",
    approver: str = "",
) -> Iterator[dict[str, Any]]:
    for target, _ in parse_targets(events):
        if target is None:
            continue

        denied, matched = is_protected_namespace(target.namespace, deny_namespaces)
        if denied:
            status = STATUS_SKIPPED_DENY_LIST if apply else STATUS_WOULD_VIOLATE_DENY_LIST
            yield _skip_record(
                target,
                status=status,
                detail=f"namespace `{target.namespace}` matched protected pattern `{matched}`",
                dry_run=not apply and not reverify,
            )
            continue

        resolved = resolve_target(target, kube_client)
        if resolved is None:
            dry_run = not apply and not reverify
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_UNSUPPORTED_TARGET,
                detail="could not resolve a pod or workload selector for quarantine planning",
                dry_run=dry_run,
            )
            continue

        if reverify:
            yield reverify_quarantine(resolved, kube_client=kube_client)
            continue

        if not apply:
            yield _plan_record(resolved, status=STATUS_PLANNED, detail="dry-run: would apply quarantine NetworkPolicy", dry_run=True)
            continue

        if audit is None:
            raise ValueError("audit writer is required under --apply")
        yield apply_quarantine(
            resolved,
            kube_client=kube_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify Kubernetes container-escape quarantine NetworkPolicies."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument("--apply", action="store_true", help="Apply the quarantine NetworkPolicy after approval gates pass.")
    parser.add_argument("--reverify", action="store_true", help="Read-only verification: confirm the quarantine NetworkPolicy is still present.")
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        kube_client = KubernetesApiClient()
        audit: AuditWriter | None = None
        incident_id = ""
        approver = ""
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.getenv("K8S_CONTAINER_ESCAPE_INCIDENT_ID", "").strip()
            approver = os.getenv("K8S_CONTAINER_ESCAPE_APPROVER", "").strip()
            audit = DualAuditWriter(
                dynamodb_table=os.environ["K8S_REMEDIATION_AUDIT_DYNAMODB_TABLE"],
                s3_bucket=os.environ["K8S_REMEDIATION_AUDIT_BUCKET"],
                kms_key_arn=os.environ["KMS_KEY_ARN"],
            )

        for record in run(
            load_jsonl(in_stream),
            kube_client=kube_client,
            apply=args.apply,
            reverify=args.reverify,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
        ):
            out_stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
