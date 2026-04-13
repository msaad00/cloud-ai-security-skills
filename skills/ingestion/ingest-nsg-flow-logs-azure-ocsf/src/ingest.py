"""Convert Azure NSG Flow Logs to OCSF 1.8 Network Activity (class 4001)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "ingest-nsg-flow-logs-azure-ocsf"
OCSF_VERSION = "1.8.0"

CLASS_UID = 4001
CLASS_NAME = "Network Activity"
CATEGORY_UID = 4
CATEGORY_NAME = "Network Activity"

ACTIVITY_UNKNOWN = 0
ACTIVITY_TRAFFIC = 6
ACTIVITY_DENIED = 7

SEVERITY_INFORMATIONAL = 1
STATUS_SUCCESS = 1


def protocol_name(value: str | int | None) -> str:
    mapping = {
        "T": "TCP",
        "TCP": "TCP",
        "U": "UDP",
        "UDP": "UDP",
        "I": "ICMP",
        "ICMP": "ICMP",
    }
    if value is None or value == "":
        return ""
    return mapping.get(str(value).upper(), str(value).upper())


def activity_id_for_decision(value: str | None) -> int:
    mapping = {"A": ACTIVITY_TRAFFIC, "ALLOW": ACTIVITY_TRAFFIC, "D": ACTIVITY_DENIED, "DENY": ACTIVITY_DENIED}
    if value is None or value == "":
        return ACTIVITY_UNKNOWN
    return mapping.get(str(value).upper(), ACTIVITY_UNKNOWN)


def parse_ts_ms(value: str | int | None) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        raw = int(value)
        return raw if raw > 10_000_000_000 else raw * 1000
    try:
        cleaned = str(value).replace("Z", "+00:00")
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
        return None


def _extract_subscription_id(resource_id: str) -> str:
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


def parse_flow_tuple(value: str, version: int | str = 2) -> dict[str, str]:
    parts = [part.strip() for part in value.split(",")]
    version_num = int(version)
    if version_num >= 2 and len(parts) >= 13:
        keys = (
            "time",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "direction",
            "decision",
            "flow_state",
            "packets_out",
            "bytes_out",
            "packets_in",
            "bytes_in",
        )
        return dict(zip(keys, parts[: len(keys)]))
    keys = ("time", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "direction", "decision")
    return dict(zip(keys, parts[: len(keys)]))


def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def convert_tuple(
    tuple_data: dict[str, str],
    *,
    resource_id: str,
    rule: str,
    mac: str,
    location: str = "",
) -> dict[str, Any]:
    time_ms = parse_ts_ms(tuple_data.get("time")) or int(datetime.now(timezone.utc).timestamp() * 1000)
    bytes_total = sum(value for value in (_int_or_none(tuple_data.get("bytes_out")), _int_or_none(tuple_data.get("bytes_in"))) if value is not None)
    packets_total = sum(value for value in (_int_or_none(tuple_data.get("packets_out")), _int_or_none(tuple_data.get("packets_in"))) if value is not None)
    activity_id = activity_id_for_decision(tuple_data.get("decision"))

    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": STATUS_SUCCESS,
        "time": time_ms,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "cloud-security",
                "vendor_name": "msaad00/cloud-security",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "azure", "nsg-flow-logs", "ingest"],
        },
        "src_endpoint": {
            "ip": tuple_data.get("src_ip", ""),
            **({"port": int(tuple_data["src_port"])} if tuple_data.get("src_port", "").isdigit() else {}),
            **({"interface_uid": mac} if mac else {}),
        },
        "dst_endpoint": {
            "ip": tuple_data.get("dst_ip", ""),
            **({"port": int(tuple_data["dst_port"])} if tuple_data.get("dst_port", "").isdigit() else {}),
        },
        "traffic": {},
        "connection_info": {
            **({"protocol_name": protocol_name(tuple_data.get("protocol"))} if protocol_name(tuple_data.get("protocol")) else {}),
            "direction": "egress" if tuple_data.get("direction") == "O" else "ingress",
            "boundary": resource_id,
        },
        "cloud": {"provider": "Azure"},
        "observables": [
            {"name": "azure.nsg.rule", "type": "Other", "value": rule},
            {"name": "azure.flow_state", "type": "Other", "value": tuple_data.get("flow_state", "")},
        ],
    }
    if protocol := tuple_data.get("protocol"):
        if protocol == "T":
            event["connection_info"]["protocol_num"] = 6
        elif protocol == "U":
            event["connection_info"]["protocol_num"] = 17
        elif protocol == "I":
            event["connection_info"]["protocol_num"] = 1
    if bytes_total:
        event["traffic"]["bytes"] = bytes_total
    if packets_total:
        event["traffic"]["packets"] = packets_total
    if subscription_id := _extract_subscription_id(resource_id):
        event["cloud"]["account"] = {"uid": subscription_id}
    if location:
        event["cloud"]["region"] = location
    return event


def iter_raw_records(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
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
                yield obj
        return

    items = parsed if isinstance(parsed, list) else [parsed]
    for item in items:
        if not isinstance(item, dict):
            continue
        records = item.get("records") or item.get("Records")
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict):
                    yield record
        else:
            yield item


def ingest(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for record in iter_raw_records(stream):
        properties = record.get("properties") or {}
        version = properties.get("Version") or properties.get("version") or 2
        resource_id = record.get("resourceId") or record.get("resourceID") or ""
        location = record.get("location") or properties.get("location") or ""
        for flow_group in properties.get("flows") or []:
            rule = flow_group.get("rule") or ""
            for flow in flow_group.get("flows") or []:
                mac = flow.get("mac") or ""
                for tuple_value in flow.get("flowTuples") or []:
                    tuple_data = parse_flow_tuple(tuple_value, version)
                    if tuple_data:
                        yield convert_tuple(tuple_data, resource_id=resource_id, rule=rule, mac=mac, location=location)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert Azure NSG Flow Logs to OCSF 1.8 Network Activity JSONL.")
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
