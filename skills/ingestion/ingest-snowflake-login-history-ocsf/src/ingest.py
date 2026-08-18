"""Convert Snowflake ACCOUNT_USAGE.LOGIN_HISTORY rows to OCSF 1.8 Authentication.

Input:  JSONL (or a JSON array) of ACCOUNT_USAGE.LOGIN_HISTORY rows, as returned
        by `source-snowflake-query`. Well-known columns (uppercase, per Snowflake
        docs): EVENT_ID, EVENT_TIMESTAMP, EVENT_TYPE, USER_NAME, CLIENT_IP,
        REPORTED_CLIENT_TYPE, FIRST_AUTHENTICATION_FACTOR,
        SECOND_AUTHENTICATION_FACTOR, IS_SUCCESS, ERROR_CODE, ERROR_MESSAGE,
        RELATED_EVENT_ID. Optional enrichment a collector may join in from
        ACCOUNT_USAGE.USERS on USER_NAME: USER_TYPE and USER_EMAIL / LOGIN_NAME.
Output: OCSF 1.8 Authentication (class 3002) JSONL carrying an
        `unmapped.snowflake.*` block, OR the repo-owned native projection.

Every LOGIN_HISTORY row is an authentication attempt, so every row with an
attributable USER_NAME is emitted (success and failure alike) — unlike the
QUERY_HISTORY producer, which only emits control-plane statements. The
`unmapped.snowflake.{authentication_method,error_code,is_success}` block is what
`detect-snowflake-failed-mfa-burst` anchors on. Rows without a USER_NAME are
skipped cleanly (never crash), with a diagnostic count on stderr.

Contract: see ../SKILL.md, ../REFERENCES.md, and
skills/detection-engineering/OCSF_CONTRACT.md

"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "ingest-snowflake-login-history-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
PRODUCT_NAME = "cloud-ai-security-skills"
OUTPUT_FORMATS = ("ocsf", "native")

AUTH_CLASS_UID = 3002
AUTH_CLASS_NAME = "Authentication"
AUTH_CATEGORY_UID = 3
AUTH_CATEGORY_NAME = "Identity & Access Management"
# LOGIN_HISTORY records login attempts; OCSF activity is always Logon (1), and
# status_id distinguishes success from failure. This mirrors the repo's other
# authentication producers (Okta, Google Workspace).
AUTH_ACTIVITY_LOGON = 1
AUTH_TYPE_UID = AUTH_CLASS_UID * 100 + AUTH_ACTIVITY_LOGON

SERVICE_NAME = "snowflake.login"

SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

# IS_SUCCESS is a VARCHAR ('YES' / 'NO') per the Snowflake LOGIN_HISTORY view.
_TRUE_TOKENS = frozenset({"YES", "TRUE", "1", "Y", "T"})


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def parse_ts_ms(value: Any) -> int:
    """Parse EVENT_TIMESTAMP (ISO-8601 string or epoch seconds/ms) to epoch ms."""
    if value is None or value == "":
        return _now_ms()
    if isinstance(value, (int, float)):
        # Heuristic: values >= 1e12 are already milliseconds.
        return int(value) if value >= 1_000_000_000_000 else int(value * 1000)
    text = str(value).strip()
    if not text:
        return _now_ms()
    if text.isdigit():
        num = int(text)
        return num if num >= 1_000_000_000_000 else num * 1000
    try:
        cleaned = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return _now_ms()


def _get(row: dict[str, Any], *names: str) -> Any:
    """Case-insensitive column lookup. Snowflake emits uppercase column names,
    but collectors sometimes lowercase them — accept either."""
    for name in names:
        if name in row:
            return row[name]
    lowered = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        key = name.lower()
        if key in lowered:
            return lowered[key]
    return None


def _is_success(row: dict[str, Any]) -> bool:
    raw = _get(row, "IS_SUCCESS")
    if isinstance(raw, bool):
        return raw
    return str(raw or "").strip().upper() in _TRUE_TOKENS


def _authentication_method(row: dict[str, Any]) -> str:
    """Derive the authentication method the detector reasons over.

    Prefers the second authentication factor (the MFA factor) when present,
    falling back to the first factor. `detect-snowflake-failed-mfa-burst` matches
    MFA markers (MFA / DUO / TOTP / WEBAUTHN / PASSCODE / PUSH …) in this value.
    """
    first = str(_get(row, "FIRST_AUTHENTICATION_FACTOR") or "").strip()
    second = str(_get(row, "SECOND_AUTHENTICATION_FACTOR") or "").strip()
    return second or first


def _error_code(row: dict[str, Any]) -> str:
    raw = _get(row, "ERROR_CODE")
    if raw is None:
        return ""
    text = str(raw).strip()
    # ERROR_CODE is a NUMBER; collectors sometimes serialize it as a float.
    if text.endswith(".0"):
        text = text[:-2]
    return text


def _snowflake_block(row: dict[str, Any]) -> dict[str, Any]:
    block: dict[str, Any] = {
        "authentication_method": _authentication_method(row),
        "is_success": _is_success(row),
        "error_code": _error_code(row),
    }
    error_message = str(_get(row, "ERROR_MESSAGE") or "").strip()
    if error_message:
        block["error_message"] = error_message
    first = str(_get(row, "FIRST_AUTHENTICATION_FACTOR") or "").strip()
    if first:
        block["first_authentication_factor"] = first
    second = str(_get(row, "SECOND_AUTHENTICATION_FACTOR") or "").strip()
    if second:
        block["second_authentication_factor"] = second
    event_type = str(_get(row, "EVENT_TYPE") or "").strip()
    if event_type:
        block["event_type"] = event_type
    reported_client = str(_get(row, "REPORTED_CLIENT_TYPE") or "").strip()
    if reported_client:
        block["reported_client_type"] = reported_client
    event_id = _event_uid(row)
    if event_id:
        block["event_id"] = event_id
    return block


def _actor(row: dict[str, Any]) -> dict[str, Any]:
    user_name = str(_get(row, "USER_NAME") or "").strip()
    user: dict[str, Any] = {}
    if user_name:
        user["uid"] = user_name
    email = str(_get(row, "USER_EMAIL", "LOGIN_NAME") or "").strip()
    user["name"] = email or user_name
    if email and "@" in email:
        user["email_addr"] = email
    user_type = str(_get(row, "USER_TYPE") or "").strip().upper()
    if user_type in {"SERVICE", "LEGACY_SERVICE"}:
        user["type"] = "Service"
    else:
        user["type"] = "User"
    return {"user": user}


def _event_uid(row: dict[str, Any]) -> str:
    raw = _get(row, "EVENT_ID")
    if raw is None:
        return ""
    text = str(raw).strip()
    if text.endswith(".0"):
        text = text[:-2]
    return text


def _status_ids(row: dict[str, Any]) -> tuple[int, int]:
    if _is_success(row):
        return STATUS_SUCCESS, SEVERITY_INFORMATIONAL
    return STATUS_FAILURE, SEVERITY_LOW


def _build_ocsf(row: dict[str, Any]) -> dict[str, Any]:
    event_uid = _event_uid(row)
    status_id, severity_id = _status_ids(row)
    event: dict[str, Any] = {
        "activity_id": AUTH_ACTIVITY_LOGON,
        "category_uid": AUTH_CATEGORY_UID,
        "category_name": AUTH_CATEGORY_NAME,
        "class_uid": AUTH_CLASS_UID,
        "class_name": AUTH_CLASS_NAME,
        "type_uid": AUTH_TYPE_UID,
        "severity_id": severity_id,
        "status_id": status_id,
        "time": parse_ts_ms(_get(row, "EVENT_TIMESTAMP")),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": event_uid,
            "product": {
                "name": PRODUCT_NAME,
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
        },
        "actor": _actor(row),
    }
    client_ip = str(_get(row, "CLIENT_IP") or "").strip()
    if client_ip:
        event["src_endpoint"] = {"ip": client_ip}
    event["unmapped"] = {"snowflake": _snowflake_block(row)}
    return event


def _build_native(row: dict[str, Any]) -> dict[str, Any]:
    event_uid = _event_uid(row)
    status_id, _severity_id = _status_ids(row)
    native: dict[str, Any] = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "authentication",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "provider": "Snowflake",
        "event_uid": event_uid,
        "time_ms": parse_ts_ms(_get(row, "EVENT_TIMESTAMP")),
        "status_id": status_id,
        "status": "success" if status_id == STATUS_SUCCESS else "failure",
        "actor": _actor(row),
        "unmapped": {"snowflake": _snowflake_block(row)},
    }
    client_ip = str(_get(row, "CLIENT_IP") or "").strip()
    if client_ip:
        native["src_endpoint"] = {"ip": client_ip}
    return native


def iter_raw_rows(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    """Yield LOGIN_HISTORY row dicts from NDJSON lines or a single JSON array."""
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

    if isinstance(whole, list):
        for item in whole:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(whole, dict):
        rows = whole.get("rows") or whole.get("data")
        if isinstance(rows, list):
            for item in rows:
                if isinstance(item, dict):
                    yield item
            return
        yield whole
        return

    for lineno, raw_line in enumerate(buf, start=1):
        line = raw_line.strip()
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
                error=str(exc),
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


def ingest(
    stream: Iterable[str],
    output_format: str = "ocsf",
    skipped_counts: dict[str, int] | None = None,
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    for row in iter_raw_rows(stream):
        if not isinstance(row, dict):
            continue
        try:
            user_name = str(_get(row, "USER_NAME") or "").strip()
            if not user_name:
                if skipped_counts is not None:
                    skipped_counts["no_user"] = skipped_counts.get("no_user", 0) + 1
                continue
            if output_format == "native":
                yield _build_native(row)
            else:
                yield _build_ocsf(row)
        except Exception as exc:  # defensive: never crash on one bad row
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="parse_error",
                message=f"skipping row: parse error: {exc}",
                error=str(exc),
                event_id=_event_uid(row),
            )
            if skipped_counts is not None:
                skipped_counts["parse_error"] = skipped_counts.get("parse_error", 0) + 1
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert Snowflake ACCOUNT_USAGE.LOGIN_HISTORY rows to OCSF 1.8 "
            "Authentication (3002) or native JSONL."
        )
    )
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF Authentication events (default) or the native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    skipped_counts: dict[str, int] = {}
    emitted = 0
    try:
        for event in ingest(
            in_stream, output_format=args.output_format, skipped_counts=skipped_counts
        ):
            out_stream.write(json.dumps(event, separators=(",", ":")) + "\n")
            emitted += 1
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    emit_stderr_event(
        SKILL_NAME,
        level="info",
        event="ingest_summary",
        message=(
            f"{emitted} OCSF event(s) emitted; "
            f"{sum(skipped_counts.values())} unattributable row(s) skipped"
        ),
        emitted=emitted,
        skipped=sum(skipped_counts.values()),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
