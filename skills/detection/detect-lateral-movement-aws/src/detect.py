"""Detect AWS lateral movement by joining CloudTrail OCSF with VPC Flow OCSF.

Reads a merged OCSF 1.8 JSONL stream containing both:
  - API Activity (class 6003) from ingest-cloudtrail-ocsf (the sts:AssumeRole
    anchor events)
  - Network Activity (class 4001) from ingest-vpc-flow-logs-ocsf (the east-west
    traffic that follows)

Emits OCSF 1.8 Detection Finding (class 2004) for each distinct
(session, internal destination) tuple where an assume-role anchor
precedes a meaningful east-west flow within the correlation window.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "detect-lateral-movement-aws"
OCSF_VERSION = "1.8.0"

# Detection Finding (2004)
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
# T1021 — Remote Services (Lateral Movement tactic TA0008)
T1021_TACTIC_UID = "TA0008"
T1021_TACTIC_NAME = "Lateral Movement"
T1021_TECH_UID = "T1021"
T1021_TECH_NAME = "Remote Services"
# T1078.004 — Valid Accounts: Cloud Accounts (Persistence tactic TA0003 primary)
T1078_TACTIC_UID = "TA0003"
T1078_TACTIC_NAME = "Persistence"
T1078_TECH_UID = "T1078"
T1078_TECH_NAME = "Valid Accounts"
T1078_SUB_UID = "T1078.004"
T1078_SUB_NAME = "Cloud Accounts"

# Input class filters
API_ACTIVITY_CLASS = 6003
NETWORK_ACTIVITY_CLASS = 4001

# Network Activity activity_id 6 == ACCEPT (traffic allowed)
NET_ACTIVITY_ACCEPT = 6

# Correlation window: 15 minutes post-AssumeRole
CORRELATION_WINDOW_MS = 15 * 60 * 1000

# Byte threshold — filter out scan probes / 3-way handshake noise
MIN_BYTES = 1024

# The CloudTrail API operation we anchor on
ASSUME_ROLE_OPERATIONS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}

# RFC1918 private ranges + CGNAT shared-address range
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_rfc1918(ip_str: str) -> bool:
    """True iff `ip_str` is inside any of the private / CGNAT ranges."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)


def _short(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()[:8]


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_time(event: dict[str, Any]) -> int:
    return int(event.get("time") or 0)


def _session_uid(event: dict[str, Any]) -> str:
    return (((event.get("actor") or {}).get("session") or {}).get("uid")) or ""


def _actor_name(event: dict[str, Any]) -> str:
    return (((event.get("actor") or {}).get("user") or {}).get("name")) or ""


def _api_operation(event: dict[str, Any]) -> str:
    return ((event.get("api") or {}).get("operation")) or ""


def _dst_ip(event: dict[str, Any]) -> str:
    return (event.get("dst_endpoint") or {}).get("ip") or ""


def _dst_port(event: dict[str, Any]) -> int | None:
    port = (event.get("dst_endpoint") or {}).get("port")
    return int(port) if port is not None else None


def _src_instance(event: dict[str, Any]) -> str:
    return (event.get("src_endpoint") or {}).get("instance_uid") or ""


def _src_ip(event: dict[str, Any]) -> str:
    return (event.get("src_endpoint") or {}).get("ip") or ""


def _bytes(event: dict[str, Any]) -> int:
    try:
        return int((event.get("traffic") or {}).get("bytes") or 0)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def _build_finding(
    *,
    assume_role_event: dict[str, Any],
    flow_event: dict[str, Any],
) -> dict[str, Any]:
    session = _session_uid(assume_role_event)
    principal = _actor_name(assume_role_event)
    dst_ip = _dst_ip(flow_event)
    dst_port = _dst_port(flow_event)
    src_instance = _src_instance(flow_event)
    src_ip = _src_ip(flow_event)
    flow_bytes = _bytes(flow_event)

    dst_key = f"{dst_ip}:{dst_port}"
    uid = f"det-aws-lm-{_short(session)}-{_short(dst_key)}"

    desc = (
        f"Principal '{principal}' called {_api_operation(assume_role_event)} "
        f"(session '{session}'), and within the "
        f"{CORRELATION_WINDOW_MS // 60000}-minute correlation window an "
        f"accepted east-west flow moved {flow_bytes} bytes from "
        f"{src_instance or src_ip} to {dst_ip}:{dst_port}. This is the "
        f"canonical AWS lateral movement pattern (MITRE T1021 Remote "
        f"Services via T1078.004 Cloud Accounts) — the AssumeRole anchor "
        f"alone looks routine and the VPC Flow alone looks like normal "
        f"intra-VPC traffic, but together they tell the full pivot story."
    )

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": 1,
        "time": _event_time(flow_event) or _now_ms(),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "cloud-security",
                "vendor_name": "msaad00/cloud-security",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "aws", "lateral-movement", "multi-source"],
        },
        "finding_info": {
            "uid": uid,
            "title": "AWS lateral movement: AssumeRole chain followed by east-west traffic",
            "desc": desc,
            "types": ["aws-lateral-movement"],
            "first_seen_time": _event_time(assume_role_event),
            "last_seen_time": _event_time(flow_event),
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": T1021_TACTIC_NAME, "uid": T1021_TACTIC_UID},
                    "technique": {"name": T1021_TECH_NAME, "uid": T1021_TECH_UID},
                },
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": T1078_TACTIC_NAME, "uid": T1078_TACTIC_UID},
                    "technique": {"name": T1078_TECH_NAME, "uid": T1078_TECH_UID},
                    "sub_technique": {"name": T1078_SUB_NAME, "uid": T1078_SUB_UID},
                },
            ],
        },
        "observables": [
            {"name": "session.uid", "type": "Other", "value": session},
            {"name": "actor.name", "type": "Other", "value": principal},
            {"name": "src.instance_uid", "type": "Other", "value": src_instance},
            {"name": "src.ip", "type": "Other", "value": src_ip},
            {"name": "dst.ip", "type": "Other", "value": dst_ip},
            {"name": "dst.port", "type": "Other", "value": str(dst_port) if dst_port is not None else ""},
            {"name": "traffic.bytes", "type": "Other", "value": str(flow_bytes)},
            {"name": "window.seconds", "type": "Other", "value": str(CORRELATION_WINDOW_MS // 1000)},
            {"name": "rule", "type": "Other", "value": "aws-lateral-movement"},
        ],
        "evidence": {
            "events_observed": 2,
            "first_seen_time": _event_time(assume_role_event),
            "last_seen_time": _event_time(flow_event),
            "raw_events": [],
        },
    }


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------


def detect(events: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """Walk a merged OCSF stream. Yield one finding per (session, dst) pair.

    Deterministic output order: findings are yielded in anchor-event-time
    order (then by dst IP and port as tiebreaker).
    """
    events_list = list(events)
    # Partition the stream
    assume_role_anchors: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    for ev in events_list:
        cls = ev.get("class_uid")
        if cls == API_ACTIVITY_CLASS and _api_operation(ev) in ASSUME_ROLE_OPERATIONS:
            assume_role_anchors.append(ev)
        elif cls == NETWORK_ACTIVITY_CLASS and ev.get("activity_id") == NET_ACTIVITY_ACCEPT:
            flows.append(ev)

    # Sort for deterministic iteration
    assume_role_anchors.sort(key=_event_time)
    flows.sort(key=_event_time)

    seen: set[str] = set()
    findings: list[dict[str, Any]] = []

    for anchor in assume_role_anchors:
        anchor_time = _event_time(anchor)
        window_end = anchor_time + CORRELATION_WINDOW_MS

        for flow in flows:
            ft = _event_time(flow)
            if ft < anchor_time or ft > window_end:
                continue
            if _bytes(flow) < MIN_BYTES:
                continue
            dst = _dst_ip(flow)
            if not is_rfc1918(dst):
                continue

            session = _session_uid(anchor)
            dst_port = _dst_port(flow)
            dedup_key = f"{session}|{dst}|{dst_port}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(_build_finding(assume_role_event=anchor, flow_event=flow))

    # Final deterministic ordering by anchor time, dst ip, dst port
    findings.sort(
        key=lambda f: (
            next((o["value"] for o in f["observables"] if o["name"] == "session.uid"), ""),
            next((o["value"] for o in f["observables"] if o["name"] == "dst.ip"), ""),
            next((o["value"] for o in f["observables"] if o["name"] == "dst.port"), ""),
        )
    )
    yield from findings


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect AWS lateral movement (CloudTrail + VPC Flow join).")
    parser.add_argument("input", nargs="?", help="Merged OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="OCSF Detection Finding JSONL output. Defaults to stdout.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
