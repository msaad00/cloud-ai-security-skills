"""Convert Azure Defender for Cloud alerts to OCSF 1.8 Detection Finding."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "ingest-azure-defender-for-cloud-ocsf"
OCSF_VERSION = "1.8.0"

CLASS_UID = 2004
CLASS_NAME = "Detection Finding"
CATEGORY_UID = 2
CATEGORY_NAME = "Findings"
ACTIVITY_CREATE = 1
TYPE_UID = CLASS_UID * 100 + ACTIVITY_CREATE

STATUS_SUCCESS = 1

SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5


def parse_ts_ms(value: str | None) -> int:
    if not value:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = value.replace("Z", "+00:00")
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


def severity_to_id(value: str | None) -> int:
    mapping = {
        "INFORMATIONAL": SEVERITY_INFORMATIONAL,
        "LOW": SEVERITY_LOW,
        "MEDIUM": SEVERITY_MEDIUM,
        "HIGH": SEVERITY_HIGH,
        "CRITICAL": SEVERITY_CRITICAL,
    }
    return mapping.get((value or "").upper(), SEVERITY_INFORMATIONAL)


def _extract_subscription_id(resource_id: str) -> str:
    parts = resource_id.upper().split("/")
    try:
        idx = parts.index("SUBSCRIPTIONS")
        if idx + 1 < len(parts):
            return parts[idx + 1].lower()
    except ValueError:
        pass
    return ""


def validate_alert(alert: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(alert, dict):
        return False, "not a dict"
    props = alert.get("properties")
    if not isinstance(props, dict):
        return False, "missing properties"
    if not (props.get("alertDisplayName") or props.get("displayName")):
        return False, "missing alert title"
    if not props.get("description"):
        return False, "missing description"
    return True, ""


def _resource_id(alert: dict[str, Any]) -> str:
    props = alert.get("properties") or {}
    for item in props.get("resourceIdentifiers") or []:
        if isinstance(item, dict):
            if item.get("azureResourceId"):
                return item["azureResourceId"]
            if item.get("id"):
                return item["id"]
    resource_details = props.get("resourceDetails") or {}
    return resource_details.get("id") or resource_details.get("source") or ""


def convert_alert(alert: dict[str, Any]) -> dict[str, Any]:
    props = alert.get("properties") or {}
    alert_id = str(alert.get("id") or alert.get("name") or "")
    title = str(props.get("alertDisplayName") or props.get("displayName") or alert.get("name") or "Defender for Cloud alert")
    description = str(props.get("description") or title)
    severity = str(props.get("severity") or "Informational")
    resource_id = _resource_id(alert)
    compromised_entity = str(props.get("compromisedEntity") or "")
    remediation_steps = props.get("remediationSteps") or []
    event_time = parse_ts_ms(props.get("timeGeneratedUtc") or props.get("startTimeUtc"))
    uid = f"det-defender-{hashlib.sha256(alert_id.encode()).hexdigest()[:8]}"

    event: dict[str, Any] = {
        "activity_id": ACTIVITY_CREATE,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": TYPE_UID,
        "severity_id": severity_to_id(severity),
        "status_id": STATUS_SUCCESS,
        "time": event_time,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "cloud-security",
                "vendor_name": "msaad00/cloud-security",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "azure", "defender-for-cloud", "ingest", "passthrough"],
        },
        "finding_info": {
            "uid": uid,
            "title": title,
            "desc": description,
            "types": [str(props.get("alertType") or title)],
            "first_seen_time": event_time,
            "last_seen_time": event_time,
            "attacks": [],
        },
        "resources": [{"name": resource_id, "type": "azure-resource"}] if resource_id else [],
        "cloud": {"provider": "Azure"},
        "observables": [
            {"name": "defender.alert_id", "type": "Other", "value": alert_id},
            {"name": "defender.severity", "type": "Other", "value": severity},
            {"name": "defender.compromised_entity", "type": "Other", "value": compromised_entity},
            {"name": "defender.remediation_steps", "type": "Other", "value": " | ".join(remediation_steps) if isinstance(remediation_steps, list) else str(remediation_steps)},
        ],
        "evidence": {
            "events_observed": 1,
            "first_seen_time": event_time,
            "last_seen_time": event_time,
            "raw_events": [{"uid": alert_id, "product": "azure-defender-for-cloud"}],
        },
    }
    if subscription_id := _extract_subscription_id(resource_id):
        event["cloud"]["account"] = {"uid": subscription_id}
    if location := ((props.get("resourceDetails") or {}).get("location")):
        event["cloud"]["region"] = location
    return event


def iter_raw_alerts(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    text = "".join(stream).strip()
    if not text:
        return
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                if isinstance(obj.get("value"), list):
                    for alert in obj["value"]:
                        if isinstance(alert, dict):
                            yield alert
                else:
                    yield obj
        return

    items = parsed if isinstance(parsed, list) else [parsed]
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("value"), list):
            for alert in item["value"]:
                if isinstance(alert, dict):
                    yield alert
        else:
            yield item


def ingest(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for alert in iter_raw_alerts(stream):
        valid, reason = validate_alert(alert)
        if not valid:
            print(f"[{SKILL_NAME}] skipping alert: {reason}", file=sys.stderr)
            continue
        yield convert_alert(alert)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert Azure Defender for Cloud alerts to OCSF 1.8 Detection Finding JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON or JSONL file. Defaults to stdin.")
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
