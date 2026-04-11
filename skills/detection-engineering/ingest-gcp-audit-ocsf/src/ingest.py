"""Convert raw GCP Cloud Audit Logs to OCSF 1.8 API Activity (class 6003).

Input:  GCP audit log JSON entries (the LogEntry envelope with a
        google.cloud.audit.AuditLog protoPayload). Reads JSONL or a
        top-level array.
Output: JSONL of OCSF 1.8 API Activity events.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "ingest-gcp-audit-ocsf"
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

AUDIT_LOG_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"

# gRPC canonical error codes (subset)
_GRPC_CODE_NAMES = {
    0: "OK",
    1: "CANCELLED",
    2: "UNKNOWN",
    3: "INVALID_ARGUMENT",
    5: "NOT_FOUND",
    6: "ALREADY_EXISTS",
    7: "PERMISSION_DENIED",
    8: "RESOURCE_EXHAUSTED",
    9: "FAILED_PRECONDITION",
    10: "ABORTED",
    13: "INTERNAL",
    14: "UNAVAILABLE",
    16: "UNAUTHENTICATED",
}


# ---------------------------------------------------------------------------
# Verb → activity_id (applied to the LAST dotted segment of methodName)
# ---------------------------------------------------------------------------

_VERB_TABLE = (
    (("Create", "Insert", "Generate", "Issue", "Provision", "Allocate"), ACTIVITY_CREATE),
    (("Get", "List", "Search", "Lookup", "BatchGet", "Test", "Validate", "Aggregate"), ACTIVITY_READ),
    (("Update", "Patch", "Set", "Replace", "Add", "Enable", "Attach", "Promote"), ACTIVITY_UPDATE),
    (("Delete", "Remove", "Cancel", "Disable", "Detach", "Revoke", "Purge"), ACTIVITY_DELETE),
)


def infer_activity_id(method_name: str) -> int:
    """Map a GCP methodName to an OCSF API Activity activity_id.

    Method names look like 'google.iam.admin.v1.CreateServiceAccountKey' — we
    take the LAST dotted segment ('CreateServiceAccountKey') and match against
    the verb prefix table.

    >>> infer_activity_id("google.iam.admin.v1.CreateServiceAccountKey")
    1
    >>> infer_activity_id("google.cloud.compute.v1.Instances.List")
    2
    >>> infer_activity_id("storage.objects.delete")
    4
    """
    if not method_name:
        return ACTIVITY_OTHER
    last = method_name.rsplit(".", 1)[-1]
    # Title-case the first character so 'storage.objects.delete' matches 'Delete'
    if last and last[0].islower():
        last = last[0].upper() + last[1:]
    for prefixes, activity in _VERB_TABLE:
        for p in prefixes:
            if last.startswith(p):
                return activity
    return ACTIVITY_OTHER


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def parse_ts_ms(ts: str | None) -> int:
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        # GCP timestamps may have nanosecond precision; trim to 6 digits
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


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def _status_id_and_detail(proto_status: dict[str, Any] | None) -> tuple[int, str | None]:
    """GCP status is empty {} on success, populated with code/message on failure."""
    if not proto_status:
        return STATUS_SUCCESS, None
    code = proto_status.get("code", 0)
    if code == 0:
        return STATUS_SUCCESS, None
    msg = proto_status.get("message", "")
    name = _GRPC_CODE_NAMES.get(code, f"CODE_{code}")
    detail = f"{name}: {msg}".strip(": ").strip()
    return STATUS_FAILURE, detail or None


# ---------------------------------------------------------------------------
# Field builders
# ---------------------------------------------------------------------------


def _build_actor(auth_info: dict[str, Any]) -> dict[str, Any]:
    actor: dict[str, Any] = {}
    user: dict[str, Any] = {}
    if "principalEmail" in auth_info:
        user["name"] = auth_info["principalEmail"]
    if "principalSubject" in auth_info:
        user["uid"] = auth_info["principalSubject"]
    elif "principalEmail" in auth_info:
        user["uid"] = auth_info["principalEmail"]
    if "serviceAccountKeyName" in auth_info:
        user["type"] = "ServiceAccount"
    if user:
        actor["user"] = user
    return actor


def _build_src_endpoint(req_meta: dict[str, Any]) -> dict[str, Any]:
    src: dict[str, Any] = {}
    if "callerIp" in req_meta:
        src["ip"] = req_meta["callerIp"]
    if "callerSuppliedUserAgent" in req_meta:
        src["svc_name"] = req_meta["callerSuppliedUserAgent"]
    return src


def _build_api(proto: dict[str, Any], log_entry: dict[str, Any]) -> dict[str, Any]:
    api: dict[str, Any] = {
        "operation": proto.get("methodName", ""),
        "service": {"name": proto.get("serviceName", "")},
    }
    if "insertId" in log_entry:
        api["request"] = {"uid": log_entry["insertId"]}
    return api


def _build_resources(proto: dict[str, Any], log_entry: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    name = proto.get("resourceName", "")
    if name:
        rtype = ((log_entry.get("resource") or {}).get("type")) or ""
        resources.append({"name": name, "type": rtype})
    return resources


def _build_cloud(log_entry: dict[str, Any]) -> dict[str, Any]:
    cloud: dict[str, Any] = {"provider": "GCP"}
    labels = ((log_entry.get("resource") or {}).get("labels")) or {}
    if "project_id" in labels:
        cloud["account"] = {"uid": labels["project_id"]}
    if "location" in labels:
        cloud["region"] = labels["location"]
    return cloud


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------


def convert_event(log_entry: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one GCP LogEntry into one OCSF API Activity event.

    Returns None if the entry is not an audit log (e.g. a generic Cloud Logging
    entry from an application).
    """
    proto = log_entry.get("protoPayload") or {}
    if proto.get("@type") != AUDIT_LOG_TYPE:
        return None

    method_name = proto.get("methodName", "")
    activity_id = infer_activity_id(method_name)
    status_id, status_detail = _status_id_and_detail(proto.get("status"))

    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": status_id,
        "time": parse_ts_ms(log_entry.get("timestamp")),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "cloud-security",
                "vendor_name": "msaad00/cloud-security",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "gcp", "audit-log", "ingest"],
        },
        "actor": _build_actor(proto.get("authenticationInfo") or {}),
        "src_endpoint": _build_src_endpoint(proto.get("requestMetadata") or {}),
        "api": _build_api(proto, log_entry),
        "resources": _build_resources(proto, log_entry),
        "cloud": _build_cloud(log_entry),
    }

    if status_detail:
        event["status_detail"] = status_detail

    return event


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def iter_raw_entries(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    """Yield LogEntry dicts from JSONL or a top-level array."""
    buf: list[str] = list(stream)
    if not buf:
        return

    full = "\n".join(line.rstrip("\n") for line in buf).strip()
    if not full:
        return

    try:
        whole = json.loads(full)
    except json.JSONDecodeError:
        whole = None

    if isinstance(whole, list):
        for r in whole:
            if isinstance(r, dict):
                yield r
        return
    if isinstance(whole, dict):
        yield whole
        return

    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {e}", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def ingest(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for raw in iter_raw_entries(stream):
        try:
            event = convert_event(raw)
        except Exception as e:
            print(f"[{SKILL_NAME}] skipping entry: convert error: {e}", file=sys.stderr)
            continue
        if event is None:
            print(f"[{SKILL_NAME}] skipping entry: not a google.cloud.audit.AuditLog", file=sys.stderr)
            continue
        yield event


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw GCP audit logs to OCSF 1.8 API Activity JSONL.")
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
