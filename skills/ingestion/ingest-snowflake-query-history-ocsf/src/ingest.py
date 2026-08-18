"""Convert Snowflake ACCOUNT_USAGE.QUERY_HISTORY rows to OCSF 1.8 API Activity.

Input:  JSONL (or a JSON array) of ACCOUNT_USAGE.QUERY_HISTORY rows, as returned
        by `source-snowflake-query`. Well-known columns (uppercase, per Snowflake
        docs): QUERY_ID, QUERY_TEXT, QUERY_TYPE, USER_NAME, ROLE_NAME, START_TIME,
        EXECUTION_STATUS, ERROR_CODE, BYTES_SCANNED, ROWS_UNLOADED, WAREHOUSE_NAME.
        Optional enrichment columns a collector may join in: CLIENT_IP (from
        ACCOUNT_USAGE.SESSIONS on SESSION_ID) and USER_TYPE / USER_EMAIL (from
        ACCOUNT_USAGE.USERS on USER_NAME).
Output: OCSF 1.8 API Activity (class 6003) JSONL carrying an
        `unmapped.snowflake.*` block, OR the repo-owned native projection.

Only statements relevant to the shipped `detect-snowflake-*` rules are emitted;
QUERY_TEXT is parsed to derive `api.operation` and the per-operation
`unmapped.snowflake.*` fields. Unrecognized rows are skipped cleanly (never
crash), with a diagnostic count on stderr.

Contract: see ../SKILL.md, ../REFERENCES.md, and
skills/detection-engineering/OCSF_CONTRACT.md

"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "ingest-snowflake-query-history-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
PRODUCT_NAME = "cloud-ai-security-skills"
OUTPUT_FORMATS = ("ocsf", "native")

API_ACTIVITY_CLASS_UID = 6003
API_ACTIVITY_CLASS_NAME = "API Activity"
API_ACTIVITY_CATEGORY_UID = 6
API_ACTIVITY_CATEGORY_NAME = "Application Activity"
API_ACTIVITY_CREATE = 1
API_ACTIVITY_TYPE_UID = API_ACTIVITY_CLASS_UID * 100 + API_ACTIVITY_CREATE

SERVICE_NAME = "snowflake.warehouse"

SEVERITY_INFORMATIONAL = 1
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

# EXECUTION_STATUS values per Snowflake ACCOUNT_USAGE.QUERY_HISTORY docs.
_SUCCESS_STATUSES = frozenset({"success"})
_FAILURE_STATUSES = frozenset({"fail", "failed", "incident", "failed_with_incident"})

# Snowflake warehouse sizes in ascending order; index = ordinal scale. Matches
# the ladder used by detect-snowflake-warehouse-resize-burst.
SIZE_LADDER: tuple[str, ...] = (
    "XSMALL",
    "SMALL",
    "MEDIUM",
    "LARGE",
    "XLARGE",
    "X2LARGE",
    "X3LARGE",
    "X4LARGE",
    "X5LARGE",
    "X6LARGE",
)
# Snowflake accepts several literal spellings for a warehouse size; normalize
# them all to the ladder token. `WAREHOUSE_SIZE = 'X-Large'`, `= XLARGE`, and
# `= '2X-Large'` must land on XLARGE / X2LARGE respectively.
_SIZE_ALIASES: dict[str, str] = {
    "XSMALL": "XSMALL",
    "SMALL": "SMALL",
    "MEDIUM": "MEDIUM",
    "LARGE": "LARGE",
    "XLARGE": "XLARGE",
    "2XLARGE": "X2LARGE",
    "3XLARGE": "X3LARGE",
    "4XLARGE": "X4LARGE",
    "5XLARGE": "X5LARGE",
    "6XLARGE": "X6LARGE",
    "X2LARGE": "X2LARGE",
    "X3LARGE": "X3LARGE",
    "X4LARGE": "X4LARGE",
    "X5LARGE": "X5LARGE",
    "X6LARGE": "X6LARGE",
}
# Snowflake CREATE WAREHOUSE defaults to XSMALL; used as the prior size for the
# first observed resize of a warehouse within a QUERY_HISTORY stream.
DEFAULT_WAREHOUSE_SIZE = "XSMALL"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def parse_ts_ms(value: Any) -> int:
    """Parse START_TIME (ISO-8601 string or epoch seconds/ms) to epoch ms."""
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


def _clean_ident(token: str) -> str:
    """Strip trailing punctuation and surrounding quotes from a SQL identifier."""
    token = token.strip().strip(";").strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"', "`"}:
        token = token[1:-1]
    return token.strip()


def _status_id(execution_status: Any) -> int:
    value = str(execution_status or "").strip().lower()
    if value in _FAILURE_STATUSES:
        return STATUS_FAILURE
    if value in _SUCCESS_STATUSES:
        return STATUS_SUCCESS
    # Unknown / running / blank: default to success so ingest never invents a
    # failure. Detectors that require success still see a success record.
    return STATUS_SUCCESS


def _normalize_size(raw: str) -> str:
    key = re.sub(r"[\s_\-'\"]", "", raw).upper()
    return _SIZE_ALIASES.get(key, key)


def _split_accounts(blob: str) -> list[str]:
    """Split a `TO ACCOUNTS a, b, c` / `ADD ACCOUNTS = a, b` tail into names."""
    blob = blob.strip()
    if blob.startswith("="):
        blob = blob[1:]
    parts = re.split(r"[,\s]+", blob.strip().strip("()"))
    return [_clean_ident(part) for part in parts if _clean_ident(part)]


def _parse_ip_list(clause: str, key: str) -> list[str]:
    match = re.search(rf"{key}\s*=\s*\(([^)]*)\)", clause, re.IGNORECASE)
    if not match:
        return []
    inner = match.group(1)
    return [_clean_ident(part) for part in inner.split(",") if _clean_ident(part)]


# --- Per-operation parsers ------------------------------------------------
#
# Each returns (api_operation, unmapped_snowflake_block) for a relevant
# statement, or None. `size_state` carries per-warehouse prior sizes so a
# resize's from-size can be chained across the stream.


def _parse_grant_role(text_upper: str, text: str) -> tuple[str, dict[str, Any]] | None:
    match = re.match(r"^GRANT\s+ROLE\s+(\S+)\s+TO\s+(USER|ROLE)\s+(\S+)", text, re.IGNORECASE)
    if not match:
        return None
    granted_role = _clean_ident(match.group(1)).upper()
    grantee_kind = match.group(2).upper()
    grantee = _clean_ident(match.group(3))
    block: dict[str, Any] = {"granted_role": granted_role}
    if grantee_kind == "USER":
        block["grantee_user"] = grantee
    else:
        block["grantee_role"] = grantee
    return "GRANT_ROLE", block


def _parse_alter_user(text_upper: str, text: str) -> tuple[str, dict[str, Any]] | None:
    match = re.match(
        r"^ALTER\s+USER\s+(\S+)\s+(SET|UNSET)\s+(.+)$", text, re.IGNORECASE | re.DOTALL
    )
    if not match:
        return None
    target_user = _clean_ident(match.group(1))
    verb = match.group(2).upper()
    rest = match.group(3)
    rest_upper = rest.upper()
    if "RSA_PUBLIC_KEY_2" in rest_upper:
        statement_kind = "ALTER_USER_SET_RSA_PUBLIC_KEY_2"
        rsa_set = verb == "SET"
    elif "RSA_PUBLIC_KEY" in rest_upper:
        statement_kind = "ALTER_USER_SET_RSA_PUBLIC_KEY"
        rsa_set = verb == "SET"
    else:
        prop = re.match(r"([A-Z0-9_]+)", rest_upper.strip())
        prop_name = prop.group(1) if prop else "PROPERTY"
        statement_kind = f"ALTER_USER_{verb}_{prop_name}"
        rsa_set = False
    return "ALTER_USER", {
        "target_user": target_user,
        "statement_kind": statement_kind,
        "rsa_public_key_set": rsa_set,
    }


def _parse_alter_account_network(text_upper: str, text: str) -> tuple[str, dict[str, Any]] | None:
    if not re.match(r"^ALTER\s+ACCOUNT\s+", text, re.IGNORECASE):
        return None
    if re.search(r"\bUNSET\s+NETWORK_POLICY\b", text, re.IGNORECASE):
        return "ALTER_ACCOUNT", {
            "policy_name": "",
            "operation_kind": "account_network_policy_unset",
        }
    match = re.search(r"\bSET\s+NETWORK_POLICY\s*=\s*(\S+)", text, re.IGNORECASE)
    if match:
        return "ALTER_ACCOUNT", {
            "policy_name": _clean_ident(match.group(1)),
            "operation_kind": "account_network_policy_set",
        }
    return None


def _parse_alter_network_policy(text_upper: str, text: str) -> tuple[str, dict[str, Any]] | None:
    match = re.match(
        r"^(?:ALTER|CREATE)\s+NETWORK\s+POLICY\s+(?:IF\s+NOT\s+EXISTS\s+)?(\S+)\s+(.*)$",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    policy_name = _clean_ident(match.group(1))
    clause = match.group(2)
    allowed = _parse_ip_list(clause, "ALLOWED_IP_LIST")
    blocked = _parse_ip_list(clause, "BLOCKED_IP_LIST")
    block: dict[str, Any] = {
        "policy_name": policy_name,
        "operation_kind": "set_allowed_ip_list" if allowed else "alter_network_policy",
        "allowed_ip_list": allowed,
        "blocked_ip_list": blocked,
    }
    return "ALTER_NETWORK_POLICY", block


def _parse_alter_database_replication(
    text_upper: str, text: str
) -> tuple[str, dict[str, Any]] | None:
    match = re.match(
        r"^ALTER\s+DATABASE\s+(\S+)\s+ENABLE\s+(REPLICATION|FAILOVER)\s+TO\s+ACCOUNTS\s+(.+)$",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    database_name = _clean_ident(match.group(1))
    kind = match.group(2).upper()
    accounts = _split_accounts(match.group(3))
    if kind == "REPLICATION":
        operation = "ALTER_DATABASE_ENABLE_REPLICATION"
        operation_kind = "alter_database_enable_replication"
    else:
        operation = "ALTER_DATABASE_ENABLE_FAILOVER"
        operation_kind = "alter_database_enable_failover"
    return operation, {
        "database_name": database_name,
        "operation_kind": operation_kind,
        "target_accounts": accounts,
    }


def _parse_session_policy(text_upper: str, text: str) -> tuple[str, dict[str, Any]] | None:
    match = re.match(
        r"^(ALTER|CREATE)\s+SESSION\s+POLICY\s+(?:IF\s+NOT\s+EXISTS\s+)?(\S+)\s*(.*)$",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    verb = match.group(1).upper()
    policy_name = _clean_ident(match.group(2))
    clause = match.group(3)
    idle = re.search(r"SESSION_IDLE_TIMEOUT_MINS\s*=\s*(\d+)", clause, re.IGNORECASE)
    ui_idle = re.search(r"SESSION_UI_IDLE_TIMEOUT_MINS\s*=\s*(\d+)", clause, re.IGNORECASE)
    block: dict[str, Any] = {"policy_name": policy_name}
    if idle:
        block["session_idle_timeout_mins"] = int(idle.group(1))
    if ui_idle:
        block["session_ui_idle_timeout_mins"] = int(ui_idle.group(1))
    operation = "ALTER_SESSION_POLICY" if verb == "ALTER" else "CREATE_SESSION_POLICY"
    return operation, block


def _parse_share(text_upper: str, text: str) -> tuple[str, dict[str, Any]] | None:
    create = re.match(r"^CREATE\s+SHARE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\S+)", text, re.IGNORECASE)
    if create:
        return "CREATE_SHARE", {
            "share_name": _clean_ident(create.group(1)),
            "operation_kind": "create_share",
        }
    add = re.match(
        r"^ALTER\s+SHARE\s+(\S+)\s+ADD\s+ACCOUNTS\s*(.+)$",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if add:
        return "ALTER_SHARE_ADD_ACCOUNTS", {
            "share_name": _clean_ident(add.group(1)),
            "operation_kind": "alter_share_add_accounts",
            "target_accounts": _split_accounts(add.group(2)),
        }
    return None


def _parse_alter_warehouse(
    text_upper: str, text: str, size_state: dict[str, str]
) -> tuple[str, dict[str, Any]] | None:
    match = re.match(r"^ALTER\s+WAREHOUSE\s+(\S+)\s+(.*)$", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    warehouse_name = _clean_ident(match.group(1))
    size_match = re.search(
        r"WAREHOUSE_SIZE\s*=\s*('?[A-Za-z0-9\- ]+?'?)(?:\s|,|;|$)",
        match.group(2),
        re.IGNORECASE,
    )
    if not size_match:
        return None
    size_to = _normalize_size(size_match.group(1))
    size_from = size_state.get(warehouse_name.upper(), DEFAULT_WAREHOUSE_SIZE)
    size_state[warehouse_name.upper()] = size_to
    return "ALTER_WAREHOUSE", {
        "warehouse_name": warehouse_name,
        "warehouse_size_from": size_from,
        "warehouse_size_to": size_to,
    }


def _parse_egress(
    text_upper: str, text: str, row: dict[str, Any]
) -> tuple[str, dict[str, Any]] | None:
    query_type = str(_get(row, "QUERY_TYPE") or "").strip().upper()
    get_match = re.match(r"^GET\s+(@\S+)", text, re.IGNORECASE)
    if get_match:
        stage = _clean_ident(get_match.group(1))
        operation = "GET"
    else:
        copy_match = re.match(
            r"^COPY\s+INTO\s+(@\S+|'[^']+'|[a-zA-Z0-9]+://\S+)",
            text,
            re.IGNORECASE,
        )
        if copy_match:
            stage = _clean_ident(copy_match.group(1))
            operation = "COPY_INTO_LOCATION"
        elif query_type == "UNLOAD":
            # QUERY_TYPE authoritatively marks an unload even when the target
            # spelling is unusual; fall back to the first @stage token.
            stage_tok = re.search(r"(@\S+|'[^']+'|[a-zA-Z0-9]+://\S+)", text)
            if not stage_tok:
                return None
            stage = _clean_ident(stage_tok.group(1))
            operation = "COPY_INTO_LOCATION"
        else:
            return None
    bytes_scanned = _get(row, "BYTES_SCANNED")
    rows_unloaded = _get(row, "ROWS_UNLOADED")
    block: dict[str, Any] = {"stage_name": stage}
    if bytes_scanned is not None:
        try:
            block["bytes_scanned"] = int(bytes_scanned)
        except (TypeError, ValueError):
            pass
    if rows_unloaded is not None:
        try:
            block["rows_unloaded"] = int(rows_unloaded)
        except (TypeError, ValueError):
            pass
    return operation, block


def derive_operation(
    row: dict[str, Any], size_state: dict[str, str]
) -> tuple[str, dict[str, Any]] | None:
    """Derive (api.operation, unmapped.snowflake block) from a QUERY_HISTORY row.

    Returns None for statements not relevant to any shipped snowflake detector.
    """
    query_text = str(_get(row, "QUERY_TEXT") or "").strip()
    if not query_text:
        return None
    # Collapse whitespace so multi-line DDL parses with the same patterns.
    text = re.sub(r"\s+", " ", query_text).strip().rstrip(";").strip()
    text_upper = text.upper()

    if text_upper.startswith("GRANT ROLE"):
        return _parse_grant_role(text_upper, text)
    if text_upper.startswith("ALTER USER"):
        return _parse_alter_user(text_upper, text)
    if text_upper.startswith("ALTER ACCOUNT"):
        return _parse_alter_account_network(text_upper, text)
    if text_upper.startswith(("ALTER NETWORK POLICY", "CREATE NETWORK POLICY")):
        return _parse_alter_network_policy(text_upper, text)
    if text_upper.startswith("ALTER DATABASE"):
        return _parse_alter_database_replication(text_upper, text)
    if re.match(r"^(ALTER|CREATE)\s+SESSION\s+POLICY", text_upper):
        return _parse_session_policy(text_upper, text)
    if text_upper.startswith(("CREATE SHARE", "ALTER SHARE")):
        return _parse_share(text_upper, text)
    if text_upper.startswith("ALTER WAREHOUSE"):
        return _parse_alter_warehouse(text_upper, text, size_state)
    if text_upper.startswith(("COPY INTO", "GET ")):
        return _parse_egress(text_upper, text, row)
    return None


def _actor(row: dict[str, Any]) -> dict[str, Any]:
    user_name = str(_get(row, "USER_NAME") or "").strip()
    user: dict[str, Any] = {}
    if user_name:
        user["uid"] = user_name
    email = str(_get(row, "USER_EMAIL", "LOGIN_NAME") or "").strip()
    user["name"] = email or user_name
    user_type = str(_get(row, "USER_TYPE") or "").strip().upper()
    if user_type in {"SERVICE", "LEGACY_SERVICE"}:
        user["type"] = "Service"
    else:
        user["type"] = "User"
    return {"user": user}


def _metadata_uid(row: dict[str, Any]) -> str:
    return str(_get(row, "QUERY_ID") or "").strip()


def _build_ocsf(
    row: dict[str, Any], operation: str, snowflake_block: dict[str, Any]
) -> dict[str, Any]:
    query_id = _metadata_uid(row)
    block = dict(snowflake_block)
    if query_id:
        block["query_id"] = query_id
    status_id = _status_id(_get(row, "EXECUTION_STATUS"))
    event: dict[str, Any] = {
        "activity_id": API_ACTIVITY_CREATE,
        "category_uid": API_ACTIVITY_CATEGORY_UID,
        "category_name": API_ACTIVITY_CATEGORY_NAME,
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": API_ACTIVITY_CLASS_NAME,
        "type_uid": API_ACTIVITY_TYPE_UID,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": status_id,
        "time": parse_ts_ms(_get(row, "START_TIME")),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": query_id,
            "product": {
                "name": PRODUCT_NAME,
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
        },
        "actor": _actor(row),
        "api": {"operation": operation, "service": {"name": SERVICE_NAME}},
    }
    client_ip = str(_get(row, "CLIENT_IP") or "").strip()
    if client_ip:
        event["src_endpoint"] = {"ip": client_ip}
    event["unmapped"] = {"snowflake": block}
    return event


def _build_native(
    row: dict[str, Any], operation: str, snowflake_block: dict[str, Any]
) -> dict[str, Any]:
    query_id = _metadata_uid(row)
    block = dict(snowflake_block)
    if query_id:
        block["query_id"] = query_id
    status_id = _status_id(_get(row, "EXECUTION_STATUS"))
    native: dict[str, Any] = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "api_activity",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "provider": "Snowflake",
        "event_uid": query_id,
        "time_ms": parse_ts_ms(_get(row, "START_TIME")),
        "status_id": status_id,
        "status": "success" if status_id == STATUS_SUCCESS else "failure",
        "operation": operation,
        "actor": _actor(row),
        "unmapped": {"snowflake": block},
    }
    client_ip = str(_get(row, "CLIENT_IP") or "").strip()
    if client_ip:
        native["src_endpoint"] = {"ip": client_ip}
    return native


def iter_raw_rows(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    """Yield QUERY_HISTORY row dicts from NDJSON lines or a single JSON array."""
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

    size_state: dict[str, str] = {}
    for row in iter_raw_rows(stream):
        if not isinstance(row, dict):
            continue
        try:
            derived = derive_operation(row, size_state)
        except Exception as exc:  # defensive: never crash on one bad row
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="parse_error",
                message=f"skipping row: parse error: {exc}",
                error=str(exc),
                query_id=_metadata_uid(row),
            )
            continue
        if derived is None:
            if skipped_counts is not None:
                query_type = str(_get(row, "QUERY_TYPE") or "other").strip() or "other"
                skipped_counts[query_type] = skipped_counts.get(query_type, 0) + 1
            continue
        operation, snowflake_block = derived
        if output_format == "native":
            yield _build_native(row, operation, snowflake_block)
        else:
            yield _build_ocsf(row, operation, snowflake_block)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert Snowflake ACCOUNT_USAGE.QUERY_HISTORY rows to OCSF 1.8 "
            "API Activity (6003) or native JSONL."
        )
    )
    parser.add_argument("input", nargs="?", help="Input JSON/JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF API Activity events (default) or the native projection.",
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
            f"{sum(skipped_counts.values())} irrelevant row(s) skipped"
        ),
        emitted=emitted,
        skipped=sum(skipped_counts.values()),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
