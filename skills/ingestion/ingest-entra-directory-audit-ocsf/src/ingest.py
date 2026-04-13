"""Convert Microsoft Entra directoryAudit events to OCSF 1.8 API Activity.

Input:  Microsoft Graph directoryAudit JSON objects from /auditLogs/directoryAudits.
        Supports top-level {"value": [...]}, arrays, or JSONL of objects.
Output: JSONL of OCSF 1.8 API Activity events (class 6003).

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "ingest-entra-directory-audit-ocsf"
OCSF_VERSION = "1.8.0"

CLASS_UID = 6003
CLASS_NAME = "API Activity"
CATEGORY_UID = 6
CATEGORY_NAME = "Application Activity"

ACTIVITY_UNKNOWN = 0
ACTIVITY_CREATE = 1
ACTIVITY_READ = 2
ACTIVITY_UPDATE = 3
ACTIVITY_DELETE = 4
ACTIVITY_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_INFORMATIONAL = 1

SUPPORTED_ACTIVITIES = {
    "Add service principal credentials",
    "Update application - Certificates and secrets management",
    "Add app role assignment to service principal",
    "Create federated identity credential",
}

_OPERATION_TYPE_MAP = {
    "ADD": ACTIVITY_CREATE,
    "CREATE": ACTIVITY_CREATE,
    "ASSIGN": ACTIVITY_UPDATE,
    "UPDATE": ACTIVITY_UPDATE,
    "DELETE": ACTIVITY_DELETE,
    "REMOVE": ACTIVITY_DELETE,
}


def parse_ts_ms(ts: str | None) -> int:
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        if "." in cleaned:
            head, _, tail = cleaned.partition(".")
            frac, sep, tz = tail.partition("+")
            if not sep:
                frac, sep, tz = tail.partition("-")
            if frac and len(frac) > 6:
                frac = frac[:6]
            cleaned = head + "." + frac + (sep + tz if sep else "")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def infer_activity_id(activity_display_name: str, operation_type: str | None) -> int:
    op = (operation_type or "").upper().strip()
    if op in _OPERATION_TYPE_MAP:
        return _OPERATION_TYPE_MAP[op]

    display = (activity_display_name or "").upper()
    if display.startswith(("ADD ", "CREATE ")):
        return ACTIVITY_CREATE
    if display.startswith(("UPDATE ", "ASSIGN ")):
        return ACTIVITY_UPDATE
    if display.startswith(("DELETE ", "REMOVE ")):
        return ACTIVITY_DELETE
    if display.startswith(("GET ", "LIST ", "READ ")):
        return ACTIVITY_READ
    return ACTIVITY_OTHER


def _status_id_and_detail(entry: dict[str, Any]) -> tuple[int, str | None]:
    result = str(entry.get("result") or "").lower()
    reason = str(entry.get("resultReason") or "").strip() or None
    if result == "success":
        return STATUS_SUCCESS, None
    if result in {"failure", "timeout"}:
        return STATUS_FAILURE, reason
    return STATUS_UNKNOWN, reason


def _build_actor(entry: dict[str, Any]) -> dict[str, Any]:
    initiated = entry.get("initiatedBy") or {}
    actor: dict[str, Any] = {}
    user = initiated.get("user") or {}
    app = initiated.get("app") or {}
    out_user: dict[str, Any] = {}

    if isinstance(user, dict) and user:
        principal = user.get("userPrincipalName") or user.get("id") or user.get("displayName") or ""
        if principal:
            out_user["name"] = str(principal)
        if user.get("id"):
            out_user["uid"] = str(user["id"])
        if user.get("userPrincipalName"):
            out_user["email_addr"] = str(user["userPrincipalName"])
        if user.get("displayName"):
            out_user.setdefault("type", "User")
    elif isinstance(app, dict) and app:
        principal = app.get("displayName") or app.get("servicePrincipalId") or app.get("appId") or ""
        if principal:
            out_user["name"] = str(principal)
        if app.get("servicePrincipalId"):
            out_user["uid"] = str(app["servicePrincipalId"])
        elif app.get("appId"):
            out_user["uid"] = str(app["appId"])
        out_user["type"] = "ServicePrincipal"

    if out_user:
        actor["user"] = out_user
    return actor


def _build_src_endpoint(entry: dict[str, Any]) -> dict[str, Any]:
    initiated = entry.get("initiatedBy") or {}
    user = initiated.get("user") or {}
    src: dict[str, Any] = {}
    ip = user.get("ipAddress") or ""
    if ip:
        src["ip"] = str(ip)
    user_agent = entry.get("userAgent") or ""
    if user_agent:
        src["svc_name"] = str(user_agent)
    return src


def _build_api(entry: dict[str, Any]) -> dict[str, Any]:
    operation = str(entry.get("activityDisplayName") or "")
    service_name = str(entry.get("loggedByService") or "Microsoft Entra ID")
    api: dict[str, Any] = {
        "operation": operation,
        "service": {"name": service_name},
    }
    correlation_id = entry.get("correlationId")
    if correlation_id:
        api["request"] = {"uid": str(correlation_id)}
    return api


def _target_resources(entry: dict[str, Any]) -> list[dict[str, Any]]:
    raw = entry.get("targetResources")
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    legacy = entry.get("targetResource")
    if isinstance(legacy, list):
        return [item for item in legacy if isinstance(item, dict)]
    return []


def _build_resources(entry: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for target in _target_resources(entry):
        name = target.get("displayName") or target.get("userPrincipalName") or target.get("id") or ""
        if not name:
            continue
        resource: dict[str, Any] = {"name": str(name), "type": str(target.get("type") or "resource")}
        if target.get("id"):
            resource["uid"] = str(target["id"])
        resources.append(resource)
    return resources


def _build_cloud() -> dict[str, Any]:
    return {"provider": "Azure"}


def _metadata_uid(entry: dict[str, Any]) -> str:
    natural = str(entry.get("id") or entry.get("correlationId") or "").strip()
    if natural:
        return natural
    stable = {
        "activityDateTime": entry.get("activityDateTime", ""),
        "activityDisplayName": entry.get("activityDisplayName", ""),
        "loggedByService": entry.get("loggedByService", ""),
        "result": entry.get("result", ""),
        "initiatedBy": entry.get("initiatedBy", {}),
        "targets": [
            {
                "id": target.get("id"),
                "displayName": target.get("displayName"),
                "type": target.get("type"),
            }
            for target in _target_resources(entry)
        ],
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_event(entry: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(entry, dict):
        return False, "not a dict"
    for field in ("activityDateTime", "activityDisplayName"):
        if not entry.get(field):
            return False, f"missing required field: {field}"
    activity = str(entry.get("activityDisplayName") or "")
    if activity not in SUPPORTED_ACTIVITIES:
        return False, f"unsupported activityDisplayName: {activity}"
    return True, ""


def convert_event(entry: dict[str, Any]) -> dict[str, Any]:
    status_id, status_detail = _status_id_and_detail(entry)
    activity_id = infer_activity_id(str(entry.get("activityDisplayName") or ""), entry.get("operationType"))
    actor = _build_actor(entry)
    src_endpoint = _build_src_endpoint(entry)
    resources = _build_resources(entry)

    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": status_id,
        "time": parse_ts_ms(entry.get("activityDateTime")),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": _metadata_uid(entry),
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": "msaad00/cloud-ai-security-skills",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["identity", "entra", "graph", "directory-audit", "ingest"],
        },
        "api": _build_api(entry),
        "cloud": _build_cloud(),
        "unmapped": {
            "entra": {
                "category": entry.get("category"),
                "logged_by_service": entry.get("loggedByService"),
                "operation_type": entry.get("operationType"),
                "correlation_id": entry.get("correlationId"),
                "additional_details": entry.get("additionalDetails") or [],
            }
        },
    }
    if actor:
        event["actor"] = actor
    if src_endpoint:
        event["src_endpoint"] = src_endpoint
    if resources:
        event["resources"] = resources
    if status_detail:
        event["status_detail"] = status_detail
    return event


def iter_raw_events(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    buf = list(stream)
    if not buf:
        return
    full = "\n".join(line.rstrip("\n") for line in buf).strip()
    if not full:
        return

    try:
        whole = json.loads(full)
    except json.JSONDecodeError:
        whole = None

    if isinstance(whole, dict):
        if isinstance(whole.get("value"), list):
            for event in whole["value"]:
                if isinstance(event, dict):
                    yield event
            return
        yield whole
        return

    if isinstance(whole, list):
        for event in whole:
            if isinstance(event, dict):
                yield event
        return

    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr)
            continue
        if isinstance(obj, dict) and isinstance(obj.get("value"), list):
            for event in obj["value"]:
                if isinstance(event, dict):
                    yield event
        elif isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def ingest(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for raw in iter_raw_events(stream):
        ok, reason = validate_event(raw)
        if not ok:
            print(f"[{SKILL_NAME}] skipping event: {reason}", file=sys.stderr)
            continue
        try:
            yield convert_event(raw)
        except Exception as exc:
            print(f"[{SKILL_NAME}] skipping event: convert error: {exc}", file=sys.stderr)
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw Entra directoryAudit JSON to OCSF 1.8 API Activity JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for event in ingest(in_stream):
            out_stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
