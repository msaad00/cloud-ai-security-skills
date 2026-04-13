"""Detect cloud lateral movement by joining OCSF API Activity with Network Activity.

Reads a merged OCSF 1.8 JSONL stream containing both:
  - API Activity (class 6003) from cloud audit ingestors (the identity-pivot
    anchor events)
  - Network Activity (class 4001) from cloud flow-log ingestors (the east-west
    traffic that follows)

Emits OCSF 1.8 Detection Finding (class 2004) for each distinct
(provider, session, internal destination) tuple where a privileged-identity
anchor precedes a meaningful east-west flow within the correlation window.

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

SKILL_NAME = "detect-lateral-movement"
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

# Correlation window: 15 minutes post-anchor
CORRELATION_WINDOW_MS = 15 * 60 * 1000

# Byte threshold — filter out scan probes / 3-way handshake noise
MIN_BYTES = 1024

# Cloud identity-pivot operations we anchor on
ASSUME_ROLE_OPERATIONS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}
GCP_IDENTITY_PIVOT_SUFFIXES = (
    "GenerateAccessToken",
    "GenerateIdToken",
    "SignJwt",
    "SignBlob",
    "CreateServiceAccountKey",
)
AZURE_IDENTITY_PIVOT_OPERATIONS = {
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
    "MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION",
    "MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/ASSIGN/ACTION",
}

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


def _api_service(event: dict[str, Any]) -> str:
    return ((((event.get("api") or {}).get("service")) or {}).get("name")) or ""


def _cloud_provider(event: dict[str, Any]) -> str:
    return (((event.get("cloud") or {}).get("provider")) or "").upper()


def _cloud_account(event: dict[str, Any]) -> str:
    return ((((event.get("cloud") or {}).get("account")) or {}).get("uid")) or ""


def _provider_display(provider: str) -> str:
    return {"AWS": "AWS", "GCP": "GCP", "AZURE": "Azure"}.get(provider, provider.title() or "Cloud")


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


def is_identity_pivot_anchor(event: dict[str, Any]) -> bool:
    """Return True when an OCSF API Activity event is a high-signal pivot anchor."""
    if event.get("class_uid") != API_ACTIVITY_CLASS:
        return False

    provider = _cloud_provider(event)
    operation = _api_operation(event)
    service = _api_service(event)

    if provider == "AWS":
        return operation in ASSUME_ROLE_OPERATIONS

    if provider == "GCP":
        if service not in {"iamcredentials.googleapis.com", "iam.googleapis.com"}:
            return False
        last = operation.rsplit(".", 1)[-1]
        return any(last.endswith(suffix) for suffix in GCP_IDENTITY_PIVOT_SUFFIXES)

    if provider == "AZURE":
        return operation.upper() in AZURE_IDENTITY_PIVOT_OPERATIONS

    return False


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def _build_finding(
    *,
    anchor_event: dict[str, Any],
    flow_event: dict[str, Any],
) -> dict[str, Any]:
    session = _session_uid(anchor_event)
    principal = _actor_name(anchor_event)
    provider_code = _cloud_provider(anchor_event)
    provider = _provider_display(provider_code)
    provider_key = (provider_code or "cloud").lower()
    account = _cloud_account(anchor_event)
    dst_ip = _dst_ip(flow_event)
    dst_port = _dst_port(flow_event)
    src_instance = _src_instance(flow_event)
    src_ip = _src_ip(flow_event)
    flow_bytes = _bytes(flow_event)
    operation = _api_operation(anchor_event)

    dst_key = f"{dst_ip}:{dst_port}"
    uid = f"det-lm-{_short(provider_key)}-{_short(session)}-{_short(dst_key)}"

    desc = (
        f"Principal '{principal}' triggered identity pivot operation '{operation}' "
        f"(session '{session}'), and within the "
        f"{CORRELATION_WINDOW_MS // 60000}-minute correlation window an "
        f"accepted east-west flow moved {flow_bytes} bytes from "
        f"{src_instance or src_ip} to {dst_ip}:{dst_port}. This is the "
        f"canonical {provider} lateral movement pattern (MITRE T1021 Remote "
        f"Services via T1078.004 Cloud Accounts) — the API anchor alone looks "
        f"routine and the flow alone looks like normal intra-cloud traffic, "
        f"but together they tell the full pivot story."
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
            "labels": ["detection-engineering", provider_key, "lateral-movement", "multi-source"],
        },
        "finding_info": {
            "uid": uid,
            "title": f"{provider} lateral movement: identity pivot followed by east-west traffic",
            "desc": desc,
            "types": ["cloud-lateral-movement"],
            "first_seen_time": _event_time(anchor_event),
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
            {"name": "cloud.provider", "type": "Other", "value": provider},
            {"name": "cloud.account", "type": "Other", "value": account},
            {"name": "session.uid", "type": "Other", "value": session},
            {"name": "actor.name", "type": "Other", "value": principal},
            {"name": "anchor.operation", "type": "Other", "value": operation},
            {"name": "src.instance_uid", "type": "Other", "value": src_instance},
            {"name": "src.ip", "type": "Other", "value": src_ip},
            {"name": "dst.ip", "type": "Other", "value": dst_ip},
            {"name": "dst.port", "type": "Other", "value": str(dst_port) if dst_port is not None else ""},
            {"name": "traffic.bytes", "type": "Other", "value": str(flow_bytes)},
            {"name": "window.seconds", "type": "Other", "value": str(CORRELATION_WINDOW_MS // 1000)},
            {"name": "rule", "type": "Other", "value": "cloud-lateral-movement"},
        ],
        "evidence": {
            "events_observed": 2,
            "first_seen_time": _event_time(anchor_event),
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
    identity_anchors: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    for ev in events_list:
        cls = ev.get("class_uid")
        if is_identity_pivot_anchor(ev):
            identity_anchors.append(ev)
        elif cls == NETWORK_ACTIVITY_CLASS and ev.get("activity_id") == NET_ACTIVITY_ACCEPT:
            flows.append(ev)

    # Sort for deterministic iteration
    identity_anchors.sort(key=_event_time)
    flows.sort(key=_event_time)

    seen: set[str] = set()
    findings: list[dict[str, Any]] = []

    for anchor in identity_anchors:
        anchor_time = _event_time(anchor)
        window_end = anchor_time + CORRELATION_WINDOW_MS
        anchor_provider = _cloud_provider(anchor)
        anchor_account = _cloud_account(anchor)

        for flow in flows:
            ft = _event_time(flow)
            if ft < anchor_time or ft > window_end:
                continue
            if anchor_provider and _cloud_provider(flow) != anchor_provider:
                continue
            flow_account = _cloud_account(flow)
            if anchor_account and flow_account and flow_account != anchor_account:
                continue
            if _bytes(flow) < MIN_BYTES:
                continue
            dst = _dst_ip(flow)
            if not is_rfc1918(dst):
                continue

            session = _session_uid(anchor)
            dst_port = _dst_port(flow)
            dedup_key = f"{anchor_provider}|{session}|{dst}|{dst_port}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(_build_finding(anchor_event=anchor, flow_event=flow))

    # Final deterministic ordering by anchor time, dst ip, dst port
    findings.sort(
        key=lambda f: (
            next((o["value"] for o in f["observables"] if o["name"] == "cloud.provider"), ""),
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
    parser = argparse.ArgumentParser(description="Detect cloud lateral movement (API Activity + Network Activity join).")
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
