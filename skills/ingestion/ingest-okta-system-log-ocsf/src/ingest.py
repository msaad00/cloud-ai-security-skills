"""Convert raw Okta System Log events to OCSF 1.8 IAM events.

Input:  Okta System Log API arrays, single-event JSON, event hook wrappers,
        or NDJSON.
Output: JSONL of OCSF Identity & Access Management events across:
        - Authentication (3002)
        - Account Change (3001)
        - User Access Management (3005)

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "ingest-okta-system-log-ocsf"
OCSF_VERSION = "1.8.0"

CATEGORY_UID = 3
CATEGORY_NAME = "Identity & Access Management"

AUTH_CLASS_UID = 3002
AUTH_CLASS_NAME = "Authentication"
AUTH_ACTIVITY_LOGON = 1
AUTH_ACTIVITY_LOGOFF = 2
AUTH_ACTIVITY_OTHER = 99

ACCOUNT_CHANGE_CLASS_UID = 3001
ACCOUNT_CHANGE_CLASS_NAME = "Account Change"
ACCOUNT_CHANGE_CREATE = 1
ACCOUNT_CHANGE_ENABLE = 2
ACCOUNT_CHANGE_PASSWORD_CHANGE = 3
ACCOUNT_CHANGE_PASSWORD_RESET = 4
ACCOUNT_CHANGE_DISABLE = 5
ACCOUNT_CHANGE_DELETE = 6
ACCOUNT_CHANGE_LOCK = 9
ACCOUNT_CHANGE_MFA_ENABLE = 10
ACCOUNT_CHANGE_MFA_DISABLE = 11
ACCOUNT_CHANGE_UNLOCK = 12
ACCOUNT_CHANGE_OTHER = 99

USER_ACCESS_CLASS_UID = 3005
USER_ACCESS_CLASS_NAME = "User Access Management"
USER_ACCESS_ASSIGN = 1
USER_ACCESS_REVOKE = 2
USER_ACCESS_OTHER = 99

STATUS_UNKNOWN = 0
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

SEVERITY_UNKNOWN = 0
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4

_AUTH_EVENT_MAP: dict[str, int] = {
    "user.session.start": AUTH_ACTIVITY_LOGON,
    "user.session.end": AUTH_ACTIVITY_LOGOFF,
    "user.authentication.sso": AUTH_ACTIVITY_LOGON,
}

_ACCOUNT_CHANGE_EVENT_MAP: dict[str, int] = {
    "user.lifecycle.create": ACCOUNT_CHANGE_CREATE,
    "user.lifecycle.activate": ACCOUNT_CHANGE_ENABLE,
    "user.lifecycle.unsuspend": ACCOUNT_CHANGE_ENABLE,
    "user.lifecycle.deactivate": ACCOUNT_CHANGE_DISABLE,
    "user.lifecycle.suspend": ACCOUNT_CHANGE_DISABLE,
    "user.account.update_password": ACCOUNT_CHANGE_PASSWORD_CHANGE,
    "user.account.reset_password": ACCOUNT_CHANGE_PASSWORD_RESET,
    "user.account.lock": ACCOUNT_CHANGE_LOCK,
    "user.account.unlock_by_admin": ACCOUNT_CHANGE_UNLOCK,
    "user.mfa.factor.activate": ACCOUNT_CHANGE_MFA_ENABLE,
    "user.mfa.factor.deactivate": ACCOUNT_CHANGE_MFA_DISABLE,
}

_USER_ACCESS_EVENT_MAP: dict[str, int] = {
    "application.user_membership.add": USER_ACCESS_ASSIGN,
    "application.user_membership.remove": USER_ACCESS_REVOKE,
    "group.user_membership.add": USER_ACCESS_ASSIGN,
    "group.user_membership.remove": USER_ACCESS_REVOKE,
    "user.account.privilege.grant": USER_ACCESS_ASSIGN,
    "user.account.privilege.revoke": USER_ACCESS_REVOKE,
}


def parse_ts_ms(ts: str | None) -> int:
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def severity_to_id(severity: str | None) -> int:
    value = (severity or "").upper()
    if value in {"INFO", "INFORMATIONAL", "DEBUG"}:
        return SEVERITY_INFORMATIONAL
    if value in {"WARN", "WARNING"}:
        return SEVERITY_LOW
    if value in {"ERROR"}:
        return SEVERITY_HIGH
    return SEVERITY_UNKNOWN


def status_from_outcome(outcome: dict[str, Any] | None) -> tuple[int, str | None]:
    if not isinstance(outcome, dict):
        return STATUS_UNKNOWN, None
    result = (outcome.get("result") or "").upper()
    reason = outcome.get("reason") or None
    if result == "SUCCESS":
        return STATUS_SUCCESS, None
    if result == "FAILURE":
        return STATUS_FAILURE, str(reason) if reason else None
    return STATUS_UNKNOWN, str(reason) if reason else None


def _classify_event(event_type: str) -> tuple[int, str, int] | None:
    if event_type in _AUTH_EVENT_MAP:
        return AUTH_CLASS_UID, AUTH_CLASS_NAME, _AUTH_EVENT_MAP[event_type]
    if event_type in _ACCOUNT_CHANGE_EVENT_MAP:
        return ACCOUNT_CHANGE_CLASS_UID, ACCOUNT_CHANGE_CLASS_NAME, _ACCOUNT_CHANGE_EVENT_MAP[event_type]
    if event_type in _USER_ACCESS_EVENT_MAP:
        return USER_ACCESS_CLASS_UID, USER_ACCESS_CLASS_NAME, _USER_ACCESS_EVENT_MAP[event_type]
    return None


def _user_object(entity: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(entity, dict):
        return {}
    user: dict[str, Any] = {}
    if entity.get("id"):
        user["uid"] = str(entity["id"])
    name = entity.get("alternateId") or entity.get("displayName") or entity.get("id") or ""
    if name:
        user["name"] = str(name)
    if entity.get("type"):
        user["type"] = str(entity["type"])
    alt = entity.get("alternateId") or ""
    if isinstance(alt, str) and "@" in alt:
        user["email_addr"] = alt
    return user


def _find_target(event: dict[str, Any], allowed_types: set[str]) -> dict[str, Any] | None:
    for target in event.get("target") or []:
        if not isinstance(target, dict):
            continue
        if str(target.get("type") or "") in allowed_types:
            return target
    return None


def _actor(event: dict[str, Any]) -> dict[str, Any]:
    user = _user_object(event.get("actor") or {})
    return {"user": user} if user else {}


def _subject_user(event: dict[str, Any]) -> dict[str, Any]:
    target_user = _find_target(event, {"User"})
    user = _user_object(target_user or event.get("actor") or {})
    return user


def _src_endpoint(event: dict[str, Any]) -> dict[str, Any]:
    client = event.get("client") or {}
    request = event.get("request") or {}
    ip = client.get("ipAddress") or ""
    if not ip:
        ip_chain = request.get("ipChain") or []
        if ip_chain and isinstance(ip_chain[0], dict):
            ip = ip_chain[0].get("ip") or ""
    endpoint: dict[str, Any] = {}
    if ip:
        endpoint["ip"] = ip
    user_agent = (client.get("userAgent") or {}).get("rawUserAgent") or ""
    if user_agent:
        endpoint["svc_name"] = user_agent
    return endpoint


def _session(event: dict[str, Any]) -> dict[str, Any]:
    auth_ctx = event.get("authenticationContext") or {}
    session: dict[str, Any] = {}
    if auth_ctx.get("externalSessionId"):
        session["uid"] = str(auth_ctx["externalSessionId"])
    if auth_ctx.get("rootSessionId"):
        session["issuer"] = str(auth_ctx["rootSessionId"])
    return session


def _resources(event: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for target in event.get("target") or []:
        if not isinstance(target, dict):
            continue
        if str(target.get("type") or "") == "User":
            continue
        name = target.get("displayName") or target.get("alternateId") or target.get("id") or ""
        if not name:
            continue
        resources.append({"name": str(name), "type": str(target.get("type") or "resource")})
    return resources


def _privileges(event: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for target in event.get("target") or []:
        if not isinstance(target, dict):
            continue
        if str(target.get("type") or "") == "User":
            continue
        detail = target.get("detailEntry")
        if isinstance(detail, str) and detail:
            values.append(detail)
            continue
        for key in ("displayName", "alternateId", "id"):
            value = target.get(key)
            if isinstance(value, str) and value:
                values.append(value)
                break
    if not values:
        values.append(str(event.get("eventType") or "unknown"))
    return values


def _metadata_uid(event: dict[str, Any]) -> str:
    natural = str(event.get("uuid") or "").strip()
    if natural:
        return natural
    stable = {
        "published": event.get("published", ""),
        "eventType": event.get("eventType", ""),
        "actorId": (event.get("actor") or {}).get("id", ""),
        "targetIds": [target.get("id") for target in event.get("target") or [] if isinstance(target, dict)],
        "transactionId": (event.get("transaction") or {}).get("id", ""),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _base_event(event: dict[str, Any], class_uid: int, class_name: str, activity_id: int) -> dict[str, Any]:
    status_id, status_detail = status_from_outcome(event.get("outcome") or {})
    base: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": class_uid,
        "class_name": class_name,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity_to_id(event.get("severity")),
        "status_id": status_id,
        "time": parse_ts_ms(event.get("published")),
        "message": str(event.get("displayMessage") or event.get("eventType") or class_name),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": _metadata_uid(event),
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": "msaad00/cloud-ai-security-skills",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["identity", "okta", "system-log", "ingest"],
        },
        "actor": _actor(event),
        "src_endpoint": _src_endpoint(event),
        "unmapped": {
            "okta": {
                "event_type": event.get("eventType"),
                "legacy_event_type": event.get("legacyEventType"),
                "transaction_id": (event.get("transaction") or {}).get("id"),
                "root_session_id": (event.get("authenticationContext") or {}).get("rootSessionId"),
            }
        },
    }
    if status_detail:
        base["status_detail"] = status_detail
    return base


def _build_authentication_event(event: dict[str, Any], activity_id: int) -> dict[str, Any]:
    out = _base_event(event, AUTH_CLASS_UID, AUTH_CLASS_NAME, activity_id)
    user = _subject_user(event)
    if user:
        out["user"] = user
    session = _session(event)
    if session:
        out["session"] = session
    resources = _resources(event)
    if resources:
        out["resources"] = resources
        out["service"] = {"name": resources[0]["name"]}
    return out


def _build_account_change_event(event: dict[str, Any], activity_id: int) -> dict[str, Any]:
    out = _base_event(event, ACCOUNT_CHANGE_CLASS_UID, ACCOUNT_CHANGE_CLASS_NAME, activity_id)
    out["user"] = _subject_user(event)
    resources = _resources(event)
    if resources:
        out["resources"] = resources
    return out


def _build_user_access_event(event: dict[str, Any], activity_id: int) -> dict[str, Any]:
    out = _base_event(event, USER_ACCESS_CLASS_UID, USER_ACCESS_CLASS_NAME, activity_id)
    out["user"] = _subject_user(event)
    out["resources"] = _resources(event)
    out["privileges"] = _privileges(event)
    return out


def validate_event(event: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(event, dict):
        return False, "not a dict"
    for field in ("eventType", "published"):
        if not event.get(field):
            return False, f"missing required field: {field}"
    if _classify_event(str(event.get("eventType") or "")) is None:
        return False, f"unsupported eventType: {event.get('eventType')}"
    return True, ""


def convert_event(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("eventType") or "")
    route = _classify_event(event_type)
    if route is None:
        raise ValueError(f"unsupported eventType: {event_type}")

    class_uid, _class_name, activity_id = route
    if class_uid == AUTH_CLASS_UID:
        return _build_authentication_event(event, activity_id)
    if class_uid == ACCOUNT_CHANGE_CLASS_UID:
        return _build_account_change_event(event, activity_id)
    if class_uid == USER_ACCESS_CLASS_UID:
        return _build_user_access_event(event, activity_id)
    raise ValueError(f"unsupported class route for {event_type}")


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
        if isinstance(((whole.get("data") or {}).get("events")), list):
            for event in (whole.get("data") or {}).get("events") or []:
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
        if isinstance(obj, dict) and isinstance(((obj.get("data") or {}).get("events")), list):
            for event in (obj.get("data") or {}).get("events") or []:
                if isinstance(event, dict):
                    yield event
        elif isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object or Okta wrapper", file=sys.stderr)


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
    parser = argparse.ArgumentParser(description="Convert raw Okta System Log JSON to OCSF 1.8 IAM JSONL.")
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
