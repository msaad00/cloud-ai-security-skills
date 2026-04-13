"""Convert raw Azure Activity Logs to OCSF 1.8 API Activity (class 6003).

Input:  Azure Activity Log JSON entries (the shape Azure Monitor exports to
        Event Hubs / Storage / Log Analytics). Reads JSONL or a top-level array.
Output: JSONL of OCSF 1.8 API Activity events.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "ingest-azure-activity-ocsf"
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


# ---------------------------------------------------------------------------
# Verb → activity_id
# ---------------------------------------------------------------------------

# Azure operationName looks like 'PROVIDER/RESOURCETYPE/ACTION', e.g.
# 'MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE'. We classify by the LAST segment.

_VERB_MAP = {
    # Create
    "WRITE": ACTIVITY_CREATE,  # Azure overloads WRITE for both create + update; treat as Create
    "CREATE": ACTIVITY_CREATE,
    "REGENERATE": ACTIVITY_CREATE,
    "GENERATEKEY": ACTIVITY_CREATE,
    # Read
    "READ": ACTIVITY_READ,
    "LIST": ACTIVITY_READ,
    "GET": ACTIVITY_READ,
    "LISTKEYS": ACTIVITY_READ,
    "LISTACCOUNTSAS": ACTIVITY_READ,
    "LISTSERVICESAS": ACTIVITY_READ,
    "VALIDATE": ACTIVITY_READ,  # validate is read-only despite the name
    # Update
    "UPDATE": ACTIVITY_UPDATE,
    "MOVE": ACTIVITY_UPDATE,
    "RESTART": ACTIVITY_UPDATE,
    "START": ACTIVITY_UPDATE,
    # Delete
    "DELETE": ACTIVITY_DELETE,
    "STOP": ACTIVITY_DELETE,
    "DEALLOCATE": ACTIVITY_DELETE,
}


def infer_activity_id(operation_name: str) -> int:
    """Map an Azure operationName to an OCSF API Activity activity_id.

    Azure uses `/ACTION` as a generic suffix on operations that don't fit
    standard CRUD (e.g. `RESTART/ACTION`, `LISTSNAPSHOTS/ACTION`). When we see
    that suffix the meaningful verb is the segment before it; we walk
    backwards and try each segment until we hit something we recognise.

    >>> infer_activity_id("MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE")
    1
    >>> infer_activity_id("MICROSOFT.COMPUTE/VIRTUALMACHINES/READ")
    2
    >>> infer_activity_id("MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE")
    4
    >>> infer_activity_id("MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTART/ACTION")
    3
    """
    if not operation_name:
        return ACTIVITY_OTHER
    segments = [s.upper() for s in operation_name.split("/") if s]
    # Walk backwards, skipping the generic ACTION suffix until we find a
    # segment in the verb table.
    for segment in reversed(segments):
        if segment == "ACTION":
            continue
        if segment in _VERB_MAP:
            return _VERB_MAP[segment]
    return ACTIVITY_OTHER


def _service_name_from_operation(operation_name: str) -> str:
    """Extract a service-like name from the provider segment of operationName.

    'MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE' -> 'microsoft.storage'
    """
    if not operation_name:
        return ""
    return operation_name.split("/", 1)[0].lower()


def _resource_type_from_operation(operation_name: str) -> str:
    """Extract the resource type segment.

    'MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE' -> 'storageAccounts'
    """
    parts = operation_name.split("/")
    if len(parts) >= 2:
        return parts[1].lower()
    return ""


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def parse_ts_ms(ts: str | None) -> int:
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        # Azure can emit 7-digit fractional seconds (.0000000); trim to 6
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


def _status_id_and_detail(entry: dict[str, Any]) -> tuple[int, str | None]:
    """Derive status_id from resultType, falling back to properties.statusCode."""
    result_type = (entry.get("resultType") or "").lower()
    result_signature = entry.get("resultSignature") or ""

    if result_type == "success":
        return STATUS_SUCCESS, None
    if result_type == "failure":
        return STATUS_FAILURE, result_signature or None

    # Fall back to properties.statusCode
    props = entry.get("properties") or {}
    code = props.get("statusCode") or ""
    if isinstance(code, str):
        if code.isdigit():
            n = int(code)
            if 200 <= n < 300:
                return STATUS_SUCCESS, None
            if 400 <= n < 600:
                return STATUS_FAILURE, code
        elif code in ("OK", "Accepted", "Created", "NoContent"):
            return STATUS_SUCCESS, None
        elif code in ("Forbidden", "Unauthorized", "BadRequest", "NotFound", "InternalServerError"):
            return STATUS_FAILURE, code

    return STATUS_UNKNOWN, None


# ---------------------------------------------------------------------------
# Field builders
# ---------------------------------------------------------------------------


def _build_actor(entry: dict[str, Any]) -> dict[str, Any]:
    actor: dict[str, Any] = {}
    user: dict[str, Any] = {}

    identity = entry.get("identity") or {}
    claims = identity.get("claims") or {}

    # Try UPN claim, then 'name', then 'appid', then top-level 'caller'
    upn_key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
    name = claims.get(upn_key) or claims.get("upn") or claims.get("name") or claims.get("appid") or entry.get("caller", "")
    if name:
        user["name"] = name

    appid = claims.get("appid")
    if appid:
        user["uid"] = appid
        # If only an appid is present (no UPN), this is a service principal
        if not (claims.get(upn_key) or claims.get("upn") or claims.get("name")):
            user["type"] = "ServicePrincipal"

    if user:
        actor["user"] = user

    return actor


def _build_src_endpoint(entry: dict[str, Any]) -> dict[str, Any]:
    src: dict[str, Any] = {}
    if "callerIpAddress" in entry and entry["callerIpAddress"]:
        src["ip"] = entry["callerIpAddress"]
    return src


def _build_api(entry: dict[str, Any]) -> dict[str, Any]:
    op = entry.get("operationName", "")
    api: dict[str, Any] = {
        "operation": op,
        "service": {"name": _service_name_from_operation(op)},
    }
    if "correlationId" in entry:
        api["request"] = {"uid": entry["correlationId"]}
    return api


def _build_resources(entry: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    rid = entry.get("resourceId") or ""
    if rid:
        rtype = _resource_type_from_operation(entry.get("operationName", ""))
        resources.append({"name": rid, "type": rtype})
    return resources


def _extract_subscription_id(resource_id: str) -> str:
    """Pull the subscription UUID out of an Azure resourceId.

    /SUBSCRIPTIONS/<uuid>/RESOURCEGROUPS/... → <uuid>
    """
    if not resource_id:
        return ""
    parts = resource_id.upper().split("/")
    try:
        idx = parts.index("SUBSCRIPTIONS")
        if idx + 1 < len(parts):
            return parts[idx + 1].lower()
    except ValueError:
        pass
    return ""


def _build_cloud(entry: dict[str, Any]) -> dict[str, Any]:
    cloud: dict[str, Any] = {"provider": "Azure"}
    sub = _extract_subscription_id(entry.get("resourceId") or "")
    if sub:
        cloud["account"] = {"uid": sub}
    # Azure region usually lives in properties or in the resourceId for some
    # resource types, but not consistently — leave unset unless we find it
    props = entry.get("properties") or {}
    if isinstance(props, dict) and "location" in props:
        cloud["region"] = props["location"]
    return cloud


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------


def convert_event(entry: dict[str, Any]) -> dict[str, Any]:
    """Convert one Azure Activity Log entry into one OCSF API Activity event."""
    operation_name = entry.get("operationName", "")
    activity_id = infer_activity_id(operation_name)
    status_id, status_detail = _status_id_and_detail(entry)

    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": status_id,
        "time": parse_ts_ms(entry.get("time")),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "cloud-security",
                "vendor_name": "msaad00/cloud-security",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "azure", "activity-log", "ingest"],
        },
        "actor": _build_actor(entry),
        "src_endpoint": _build_src_endpoint(entry),
        "api": _build_api(entry),
        "resources": _build_resources(entry),
        "cloud": _build_cloud(entry),
    }

    if status_detail:
        event["status_detail"] = status_detail

    return event


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def iter_raw_entries(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    """Yield Activity Log entry dicts from JSONL or a top-level array."""
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
        # Some Azure exports wrap the entries in {"records": [...]}
        if "records" in whole and isinstance(whole["records"], list):
            for r in whole["records"]:
                if isinstance(r, dict):
                    yield r
            return
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
            yield convert_event(raw)
        except Exception as e:
            print(f"[{SKILL_NAME}] skipping entry: convert error: {e}", file=sys.stderr)
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert raw Azure Activity Logs to OCSF 1.8 API Activity JSONL.")
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
