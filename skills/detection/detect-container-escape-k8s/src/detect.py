"""Detect Kubernetes container-escape signals from normalized API Activity.

Consumes OCSF 1.8 API Activity (class 6003) or the native enriched K8s audit
shape emitted by ingest-k8s-audit-ocsf. Emits OCSF 1.8 Detection Findings
(class 2004) by default, or the repo-native detection_finding shape when
--output-format native is selected.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-container-escape-k8s"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
OUTPUT_FORMATS = ("ocsf", "native")

FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5

MITRE_VERSION = "v14"

T1611_TACTIC_UID = "TA0004"
T1611_TACTIC_NAME = "Privilege Escalation"
T1611_TECH_UID = "T1611"
T1611_TECH_NAME = "Escape to Host"

T1610_TACTIC_UID = "TA0002"
T1610_TACTIC_NAME = "Execution"
T1610_TECH_UID = "T1610"
T1610_TECH_NAME = "Deploy Container"

WORKLOAD_RESOURCES = {
    "pods",
    "deployments",
    "daemonsets",
    "statefulsets",
    "replicasets",
    "replicationcontrollers",
    "jobs",
    "cronjobs",
}
PATCH_VERBS = {"patch", "update"}
RISKY_CAPABILITIES = {"CAP_SYS_ADMIN", "CAP_SYS_PTRACE"}
RISKY_HOSTPATH_PREFIXES = ("/proc", "/var/lib/docker", "/var/lib/containerd")


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _short(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()[:8]


def _severity_name(severity_id: int) -> str:
    if severity_id >= SEVERITY_CRITICAL:
        return "critical"
    if severity_id >= SEVERITY_HIGH:
        return "high"
    return "unknown"


def _resource(resources: Any) -> dict[str, Any]:
    values = resources or []
    return values[0] if values else {}


def _group_names(groups: Any) -> tuple[str, ...]:
    names: list[str] = []
    for group in groups or []:
        if isinstance(group, dict):
            name = group.get("name")
        else:
            name = group
        if name:
            names.append(str(name))
    return tuple(names)


def _unmapped_k8s(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    if not isinstance(unmapped, dict):
        return {}
    k8s = unmapped.get("k8s") or {}
    return k8s if isinstance(k8s, dict) else {}


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != 6003:
            return None
        actor_user = ((event.get("actor") or {}).get("user")) or {}
        resource = _resource(event.get("resources"))
        unmapped = _unmapped_k8s(event)
        return {
            "source_format": "ocsf",
            "provider": str(((event.get("cloud") or {}).get("provider")) or "Kubernetes"),
            "time_ms": _safe_int(event.get("time")),
            "actor_name": str(actor_user.get("name") or ""),
            "actor_type": str(actor_user.get("type") or ""),
            "actor_groups": _group_names(actor_user.get("groups")),
            "operation": str(((event.get("api") or {}).get("operation")) or ""),
            "resource_type": str(resource.get("type") or ""),
            "resource_name": str(resource.get("name") or ""),
            "namespace": str(resource.get("namespace") or ""),
            "subresource": str(resource.get("subresource") or ""),
            "request_object": unmapped.get("request_object"),
            "response_object": unmapped.get("response_object"),
            "object_ref": unmapped.get("object_ref"),
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"native", "canonical"}:
        return None

    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "api_activity":
        return None

    actor_user = ((event.get("actor") or {}).get("user")) or {}
    resource = _resource(event.get("resources"))
    unmapped = _unmapped_k8s(event)
    return {
        "source_format": schema_mode or "native",
        "provider": str(event.get("provider") or event.get("cloud_provider") or "Kubernetes"),
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "actor_name": str(event.get("actor_name") or actor_user.get("name") or ""),
        "actor_type": str(event.get("actor_type") or actor_user.get("type") or ""),
        "actor_groups": _group_names(event.get("actor_groups") or actor_user.get("groups")),
        "operation": str(event.get("operation") or event.get("api_operation") or ""),
        "resource_type": str(event.get("resource_type") or resource.get("type") or ""),
        "resource_name": str(event.get("resource_name") or resource.get("name") or ""),
        "namespace": str(event.get("namespace") or resource.get("namespace") or ""),
        "subresource": str(event.get("subresource") or resource.get("subresource") or ""),
        "request_object": unmapped.get("request_object"),
        "response_object": unmapped.get("response_object"),
        "object_ref": unmapped.get("object_ref"),
    }


def _normalized_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for event in events:
        item = _normalize_event(event)
        if item is not None:
            normalized.append(item)
    normalized.sort(key=lambda item: item["time_ms"])
    return normalized


def _build_native_finding(
    *,
    rule_id: str,
    title: str,
    desc: str,
    severity_id: int,
    tactic_uid: str,
    tactic_name: str,
    technique_uid: str,
    technique_name: str,
    actor: str,
    target: str,
    first_seen_time: int,
    last_seen_time: int,
    observables: list[dict[str, Any]],
    evidence_count: int,
) -> dict[str, Any]:
    uid = f"det-k8s-{rule_id}-{_short(actor)}-{_short(target)}"
    attack = {
        "version": MITRE_VERSION,
        "tactic_uid": tactic_uid,
        "tactic_name": tactic_name,
        "technique_uid": technique_uid,
        "technique_name": technique_name,
    }
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": uid,
        "event_uid": uid,
        "provider": "Kubernetes",
        "time_ms": last_seen_time or _now_ms(),
        "severity": _severity_name(severity_id),
        "severity_id": severity_id,
        "status": "success",
        "status_id": 1,
        "title": title,
        "description": desc,
        "finding_types": [f"k8s-{rule_id}"],
        "first_seen_time_ms": first_seen_time,
        "last_seen_time_ms": last_seen_time,
        "mitre_attacks": [attack],
        "actor_name": actor,
        "target": target,
        "rule_name": rule_id,
        "observables": observables,
        "evidence_count": evidence_count,
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
    attack = native_finding["mitre_attacks"][0]
    rendered_attack = {
        "version": attack["version"],
        "tactic": {"name": attack["tactic_name"], "uid": attack["tactic_uid"]},
        "technique": {"name": attack["technique_name"], "uid": attack["technique_uid"]},
    }
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": native_finding["severity_id"],
        "status_id": native_finding["status_id"],
        "time": native_finding["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native_finding["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": "msaad00/cloud-ai-security-skills",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "kubernetes", "container-escape", native_finding["rule_name"]],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
            "attacks": [rendered_attack],
        },
        "observables": native_finding["observables"],
        "evidence": {
            "events_observed": native_finding["evidence_count"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
            "raw_events": [],
        },
    }


def _json_patch_ops(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    ops: list[dict[str, Any]] = []
    for item in payload:
        if isinstance(item, dict) and "path" in item:
            ops.append(item)
    return ops


def _iter_capabilities(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, str)]
    return []


def _find_risky_settings(payload: Any) -> list[str]:
    found: set[str] = set()
    ops = _json_patch_ops(payload)
    if ops:
        for op in ops:
            path = str(op.get("path") or "")
            value = op.get("value")
            path_lower = path.lower()
            if path_lower.endswith("/privileged") and value is True:
                found.add("privileged=true")
            if path_lower.endswith("/hostpid") and value is True:
                found.add("hostPID=true")
            if path_lower.endswith("/hostnetwork") and value is True:
                found.add("hostNetwork=true")
            if "/capabilities/add" in path_lower:
                for cap in _iter_capabilities(value):
                    if cap in RISKY_CAPABILITIES:
                        found.add(f"capability={cap}")
            if path_lower.endswith("/capabilities") and isinstance(value, dict):
                for cap in _iter_capabilities(value.get("add")):
                    if cap in RISKY_CAPABILITIES:
                        found.add(f"capability={cap}")
        return sorted(found)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "privileged" and value is True:
                    found.add("privileged=true")
                elif key == "hostPID" and value is True:
                    found.add("hostPID=true")
                elif key == "hostNetwork" and value is True:
                    found.add("hostNetwork=true")
                elif key == "capabilities" and isinstance(value, dict):
                    for cap in _iter_capabilities(value.get("add")):
                        if cap in RISKY_CAPABILITIES:
                            found.add(f"capability={cap}")
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return sorted(found)


def _is_risky_host_path(path: str) -> bool:
    if not path:
        return False
    if path == "/":
        return True
    return any(path.startswith(prefix) for prefix in RISKY_HOSTPATH_PREFIXES)


def _find_risky_host_paths(payload: Any) -> list[str]:
    found: set[str] = set()
    ops = _json_patch_ops(payload)
    if ops:
        for op in ops:
            path = str(op.get("path") or "")
            value = op.get("value")
            path_lower = path.lower()
            if "/hostpath/path" in path_lower and isinstance(value, str) and _is_risky_host_path(value):
                found.add(value)
            elif path_lower.endswith("/hostpath") and isinstance(value, dict):
                host_path = value.get("path")
                if isinstance(host_path, str) and _is_risky_host_path(host_path):
                    found.add(host_path)
        return sorted(found)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            host_path = node.get("hostPath")
            if isinstance(host_path, dict):
                value = host_path.get("path")
                if isinstance(value, str) and _is_risky_host_path(value):
                    found.add(value)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return sorted(found)


def _extract_ephemeral_container_names(payload: Any) -> list[str]:
    names: list[str] = []
    ops = _json_patch_ops(payload)
    if ops:
        for op in ops:
            path = str(op.get("path") or "").lower()
            if "ephemeralcontainers" not in path:
                continue
            value = op.get("value")
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and item.get("name"):
                        names.append(str(item["name"]))
            elif isinstance(value, dict):
                if value.get("name"):
                    names.append(str(value["name"]))
                nested = value.get("ephemeralContainers") or value.get("ephemeralcontainers")
                if isinstance(nested, list):
                    for item in nested:
                        if isinstance(item, dict) and item.get("name"):
                            names.append(str(item["name"]))
        return sorted(set(names))

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"ephemeralContainers", "ephemeralcontainers"} and isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and item.get("name"):
                            names.append(str(item["name"]))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return sorted(set(names))


def _target(resource_type: str, namespace: str, resource_name: str, subresource: str = "") -> str:
    parts = [resource_type]
    if namespace:
        parts.append(namespace)
    if resource_name:
        parts.append(resource_name)
    if subresource:
        parts.append(subresource)
    return "/".join(parts)


def rule1_risky_spec_patch(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    normalized = _normalized_events(events)
    seen: set[str] = set()
    for event in normalized:
        if event["operation"] != "patch":
            continue
        if event["resource_type"] not in WORKLOAD_RESOURCES:
            continue
        risky_settings = _find_risky_settings(event["request_object"])
        if not risky_settings:
            continue

        actor = event["actor_name"] or "unknown"
        target = _target(event["resource_type"], event["namespace"], event["resource_name"])
        key = f"r1|{actor}|{target}|{'|'.join(risky_settings)}"
        if key in seen:
            continue
        seen.add(key)

        time_ms = event["time_ms"]
        resource_label = f"{event['resource_type']} '{event['resource_name'] or '<unnamed>'}'"
        namespace_label = f" in namespace '{event['namespace']}'" if event["namespace"] else ""
        settings_text = ", ".join(risky_settings)
        yield _build_native_finding(
            rule_id="r1-risky-spec-patch",
            title="Patch introduced escape-to-host settings on a Kubernetes workload",
            desc=(
                f"Actor '{actor}' patched {resource_label}{namespace_label} with risky settings: "
                f"{settings_text}. Privileged containers, host namespace access, and added high-risk "
                f"Linux capabilities weaken workload isolation and align to container escape-to-host "
                f"behavior. (MITRE T1611)"
            ),
            severity_id=SEVERITY_CRITICAL,
            tactic_uid=T1611_TACTIC_UID,
            tactic_name=T1611_TACTIC_NAME,
            technique_uid=T1611_TECH_UID,
            technique_name=T1611_TECH_NAME,
            actor=actor,
            target=target,
            first_seen_time=time_ms,
            last_seen_time=time_ms,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "resource.type", "type": "Other", "value": event["resource_type"]},
                {"name": "resource.name", "type": "Other", "value": event["resource_name"]},
                {"name": "namespace", "type": "Other", "value": event["namespace"]},
                {"name": "risky_settings", "type": "Other", "value": settings_text},
                {"name": "rule", "type": "Other", "value": "r1-risky-spec-patch"},
            ],
            evidence_count=1,
        )


def rule2_hostpath_injection(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    normalized = _normalized_events(events)
    seen: set[str] = set()
    for event in normalized:
        if event["operation"] != "patch":
            continue
        if event["resource_type"] not in WORKLOAD_RESOURCES:
            continue
        risky_paths = _find_risky_host_paths(event["request_object"])
        if not risky_paths:
            continue

        actor = event["actor_name"] or "unknown"
        target = _target(event["resource_type"], event["namespace"], event["resource_name"])
        path_text = ", ".join(risky_paths)
        key = f"r2|{actor}|{target}|{path_text}"
        if key in seen:
            continue
        seen.add(key)

        time_ms = event["time_ms"]
        resource_label = f"{event['resource_type']} '{event['resource_name'] or '<unnamed>'}'"
        namespace_label = f" in namespace '{event['namespace']}'" if event["namespace"] else ""
        yield _build_native_finding(
            rule_id="r2-hostpath-injection",
            title="Patch introduced a risky hostPath mount on a Kubernetes workload",
            desc=(
                f"Actor '{actor}' patched {resource_label}{namespace_label} to reference host paths "
                f"{path_text}. Kubernetes documents hostPath as a high-risk escape hatch, and these "
                f"paths map directly to host resources commonly abused during container escape. "
                f"(MITRE T1611)"
            ),
            severity_id=SEVERITY_CRITICAL,
            tactic_uid=T1611_TACTIC_UID,
            tactic_name=T1611_TACTIC_NAME,
            technique_uid=T1611_TECH_UID,
            technique_name=T1611_TECH_NAME,
            actor=actor,
            target=target,
            first_seen_time=time_ms,
            last_seen_time=time_ms,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "resource.type", "type": "Other", "value": event["resource_type"]},
                {"name": "resource.name", "type": "Other", "value": event["resource_name"]},
                {"name": "namespace", "type": "Other", "value": event["namespace"]},
                {"name": "host_paths", "type": "Other", "value": path_text},
                {"name": "rule", "type": "Other", "value": "r2-hostpath-injection"},
            ],
            evidence_count=1,
        )


def rule3_ephemeral_container_creation(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    normalized = _normalized_events(events)
    seen: set[str] = set()
    for event in normalized:
        if event["operation"] not in PATCH_VERBS:
            continue
        if event["resource_type"] != "pods":
            continue

        subresource = (event["subresource"] or "").lower()
        names = _extract_ephemeral_container_names(event["request_object"])
        if not names:
            names = _extract_ephemeral_container_names(event["response_object"])
        if subresource != "ephemeralcontainers" and not names:
            continue

        actor = event["actor_name"] or "unknown"
        target = _target(event["resource_type"], event["namespace"], event["resource_name"], "ephemeralcontainers")
        names_text = ", ".join(names) if names else "<unknown>"
        key = f"r3|{actor}|{target}|{names_text}"
        if key in seen:
            continue
        seen.add(key)

        time_ms = event["time_ms"]
        pod_label = event["resource_name"] or "<unnamed>"
        namespace = event["namespace"] or "<cluster>"
        yield _build_native_finding(
            rule_id="r3-ephemeral-container",
            title="Ephemeral container was added to a running pod",
            desc=(
                f"Actor '{actor}' modified the `pods/ephemeralcontainers` subresource for pod "
                f"'{pod_label}' in namespace '{namespace}', adding ephemeral container(s): {names_text}. "
                f"Kubernetes creates ephemeral containers through a special API handler commonly reached "
                f"through `kubectl debug`; in an adversary flow this is container deployment for interactive "
                f"execution on a live target. (MITRE T1610)"
            ),
            severity_id=SEVERITY_HIGH,
            tactic_uid=T1610_TACTIC_UID,
            tactic_name=T1610_TACTIC_NAME,
            technique_uid=T1610_TECH_UID,
            technique_name=T1610_TECH_NAME,
            actor=actor,
            target=target,
            first_seen_time=time_ms,
            last_seen_time=time_ms,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "pod.name", "type": "Other", "value": event["resource_name"]},
                {"name": "namespace", "type": "Other", "value": event["namespace"]},
                {"name": "ephemeral_containers", "type": "Other", "value": names_text},
                {"name": "rule", "type": "Other", "value": "r3-ephemeral-container"},
            ],
            evidence_count=1,
        )


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    events_list = list(events)
    native_findings: list[dict[str, Any]] = []
    native_findings.extend(rule1_risky_spec_patch(events_list))
    native_findings.extend(rule2_hostpath_injection(events_list))
    native_findings.extend(rule3_ephemeral_container_creation(events_list))
    native_findings.sort(key=lambda finding: finding["time_ms"])
    for native_finding in native_findings:
        if output_format == "native":
            yield native_finding
        else:
            yield _render_ocsf_finding(native_finding)


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect Kubernetes container-escape signals from OCSF or native API Activity events."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF findings or the native enriched finding shape.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
