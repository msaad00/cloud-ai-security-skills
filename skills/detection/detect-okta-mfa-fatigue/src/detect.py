"""Detect repeated Okta Verify push-denial bursts from OCSF Authentication events.

Reads OCSF 1.8 Authentication (class 3002) events produced by
ingest-okta-system-log-ocsf and emits OCSF 1.8 Detection Finding (class 2004)
when a single user receives repeated Okta Verify push challenges and denies or
generic MFA verification failures inside a short time window.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "detect-okta-mfa-fatigue"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"
REPO_VENDOR = "msaad00/cloud-ai-security-skills"

AUTH_CLASS_UID = 3002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_FAILURE = 2

WINDOW_MS = 10 * 60 * 1000
MIN_RELEVANT_EVENTS = 3
MIN_CHALLENGES = 2
MIN_DENIALS = 1

OKTA_INGEST_SKILL = "ingest-okta-system-log-ocsf"
CHALLENGE_EVENT_TYPES = {"system.push.send_factor_verify_push"}
DENY_EVENT_TYPES = {
    "user.mfa.okta_verify.deny_push",
    "user.mfa.okta_verify.deny_push_upgrade_needed",
}
GENERIC_MFA_EVENT_TYPE = "user.authentication.auth_via_mfa"
OKTA_VERIFY_RESOURCE_MARKERS = {"okta verify", "okta_verify"}

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0006"
MITRE_TACTIC_NAME = "Credential Access"
MITRE_TECHNIQUE_UID = "T1621"
MITRE_TECHNIQUE_NAME = "Multi-Factor Authentication Request Generation"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_time(event: dict[str, Any]) -> int:
    try:
        return int(event.get("time") or 0)
    except (TypeError, ValueError):
        return 0


def _metadata_uid(event: dict[str, Any]) -> str:
    return str((event.get("metadata") or {}).get("uid") or "")


def _okta_event_type(event: dict[str, Any]) -> str:
    return str((((event.get("unmapped") or {}).get("okta")) or {}).get("event_type") or "")


def _product_feature_name(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _user_info(event: dict[str, Any]) -> tuple[str, str]:
    user = event.get("user") or {}
    uid = str(user.get("uid") or user.get("email_addr") or user.get("name") or "").strip()
    name = str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _source_ip(event: dict[str, Any]) -> str:
    return str((event.get("src_endpoint") or {}).get("ip") or "")


def _session_uid(event: dict[str, Any]) -> str:
    return str((event.get("session") or {}).get("uid") or "")


def _resource_names(event: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        name = resource.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    service_name = (event.get("service") or {}).get("name")
    if isinstance(service_name, str) and service_name:
        names.append(service_name)
    return names


def _is_okta_verify_factor(event: dict[str, Any]) -> bool:
    normalized = {name.strip().lower() for name in _resource_names(event)}
    return any(marker in normalized for marker in OKTA_VERIFY_RESOURCE_MARKERS)


def _classify_relevant_event(event: dict[str, Any]) -> str | None:
    if event.get("class_uid") != AUTH_CLASS_UID:
        return None
    if _product_feature_name(event) != OKTA_INGEST_SKILL:
        return None

    event_type = _okta_event_type(event)
    if event_type in CHALLENGE_EVENT_TYPES:
        return "challenge"
    if event_type in DENY_EVENT_TYPES:
        return "deny"
    if (
        event_type == GENERIC_MFA_EVENT_TYPE
        and int(event.get("status_id") or 0) == STATUS_FAILURE
        and _is_okta_verify_factor(event)
    ):
        return "deny"
    return None


def _finding_uid(user_uid: str, first_uid: str, last_uid: str) -> str:
    material = f"{user_uid}|{first_uid}|{last_uid}"
    return f"det-okta-mfa-fatigue-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_finding(user_uid: str, user_name: str, burst: list[dict[str, Any]]) -> dict[str, Any]:
    first = burst[0]
    last = burst[-1]
    first_uid = _metadata_uid(first["event"])
    last_uid = _metadata_uid(last["event"])
    finding_uid = _finding_uid(user_uid, first_uid, last_uid)

    challenge_count = sum(1 for item in burst if item["kind"] == "challenge")
    denial_count = sum(1 for item in burst if item["kind"] == "deny")
    source_ips = sorted({_source_ip(item["event"]) for item in burst if _source_ip(item["event"])})
    session_uids = sorted({_session_uid(item["event"]) for item in burst if _session_uid(item["event"])})
    event_uids = [_metadata_uid(item["event"]) for item in burst]

    description = (
        f"User '{user_name or user_uid}' received {challenge_count} Okta Verify push challenge events and "
        f"{denial_count} denial or verification-failure events within {WINDOW_MS // 60000} minutes. "
        "This is a high-signal MFA fatigue pattern aligned to repeated push prompts and user rejection."
    )

    observables = [
        {"name": "user.uid", "type": "User Name", "value": user_uid},
        {"name": "user.name", "type": "User Name", "value": user_name or user_uid},
        {"name": "challenge.count", "type": "Other", "value": str(challenge_count)},
        {"name": "denial.count", "type": "Other", "value": str(denial_count)},
    ]
    observables.extend({"name": "src.ip", "type": "IP Address", "value": ip} for ip in source_ips)
    observables.extend({"name": "session.uid", "type": "Other", "value": uid} for uid in session_uids)

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": 1,
        "time": _event_time(last["event"]) or _now_ms(),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": finding_uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["identity", "okta", "mfa", "fatigue", "detection"],
        },
        "finding_info": {
            "uid": finding_uid,
            "title": "Repeated Okta Verify MFA push denials for one user",
            "desc": description,
            "types": ["okta-mfa-fatigue", "mfa-request-generation"],
            "first_seen_time": _event_time(first["event"]),
            "last_seen_time": _event_time(last["event"]),
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": MITRE_TACTIC_NAME, "uid": MITRE_TACTIC_UID},
                    "technique": {"name": MITRE_TECHNIQUE_NAME, "uid": MITRE_TECHNIQUE_UID},
                }
            ],
        },
        "observables": observables,
        "evidence": {
            "events_observed": len(burst),
            "challenge_events": challenge_count,
            "denial_events": denial_count,
            "source_ips": source_ips,
            "session_uids": session_uids,
            "raw_event_uids": event_uids,
        },
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("okta",),
        "asset_classes": ("identities", "authentication", "mfa", "sessions"),
        "attack_coverage": {
            "okta": {
                "principal_types": ["human-users"],
                "anchor_event_types": sorted(CHALLENGE_EVENT_TYPES | DENY_EVENT_TYPES | {GENERIC_MFA_EVENT_TYPE}),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "window_ms": WINDOW_MS,
        "thresholds": {
            "min_relevant_events": MIN_RELEVANT_EVENTS,
            "min_challenges": MIN_CHALLENGES,
            "min_denials": MIN_DENIALS,
        },
    }


def detect(events: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    dedupe: set[str] = set()
    states: dict[str, list[dict[str, Any]]] = {}
    active_bursts: set[str] = set()

    relevant: list[dict[str, Any]] = []
    for event in events:
        kind = _classify_relevant_event(event)
        if kind is None:
            continue
        metadata_uid = _metadata_uid(event)
        if metadata_uid and metadata_uid in dedupe:
            continue
        if metadata_uid:
            dedupe.add(metadata_uid)
        user_uid, user_name = _user_info(event)
        if not user_uid:
            continue
        relevant.append({"kind": kind, "event": event, "user_uid": user_uid, "user_name": user_name})

    relevant.sort(key=lambda item: (item["user_uid"], _event_time(item["event"]), _metadata_uid(item["event"])))

    for item in relevant:
        user_uid = item["user_uid"]
        current_time = _event_time(item["event"])
        burst = states.setdefault(user_uid, [])

        if burst and current_time - _event_time(burst[-1]["event"]) > WINDOW_MS:
            burst.clear()
            active_bursts.discard(user_uid)

        cutoff = current_time - WINDOW_MS
        burst[:] = [entry for entry in burst if _event_time(entry["event"]) >= cutoff]
        burst.append(item)

        challenge_count = sum(1 for entry in burst if entry["kind"] == "challenge")
        denial_count = sum(1 for entry in burst if entry["kind"] == "deny")
        if user_uid in active_bursts:
            continue
        if (
            len(burst) >= MIN_RELEVANT_EVENTS
            and challenge_count >= MIN_CHALLENGES
            and denial_count >= MIN_DENIALS
        ):
            yield _build_finding(user_uid, item["user_name"], burst)
            active_bursts.add(user_uid)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect repeated Okta Verify MFA push-denial bursts from OCSF.")
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Detection Finding JSONL output. Defaults to stdout.")
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
