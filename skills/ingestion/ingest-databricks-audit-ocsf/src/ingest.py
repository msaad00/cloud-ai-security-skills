"""Convert Databricks audit-log records to OCSF 1.8 API Activity (6003).

Input:  JSONL (or a JSON array) of Databricks **audit log** records — the
        workspace audit-log delivery shape (camelCase) OR the
        ``system.access.audit`` system-table shape (snake_case). Well-known
        fields (either casing accepted):
        ``serviceName`` / ``service_name``, ``actionName`` / ``action_name``,
        ``requestParams`` / ``request_params``, ``userIdentity`` /
        ``user_identity`` (with ``.email``), ``workspaceId`` /
        ``workspace_id``, ``timestamp``, ``response`` (``.statusCode`` /
        ``.status_code`` and ``.result``), ``sourceIPAddress`` /
        ``source_ip_address``, ``requestId`` / ``request_id``.
Output: OCSF 1.8 API Activity (class 6003) JSONL carrying an
        ``unmapped.databricks.*`` block, OR the repo-owned native projection.

Only ``(serviceName, actionName)`` pairs relevant to the shipped
``detect-databricks-*`` rules are emitted; the pair is resolved through an
explicit operation registry that maps the vendor-native action to the
canonical ``api.operation`` the downstream detector consumes, and derives the
per-operation ``unmapped.databricks.*`` block from ``requestParams`` /
``response.result``. Unrecognized records are skipped cleanly (never crash),
with a diagnostic count on stderr.

Contract: see ../SKILL.md, ../REFERENCES.md, and
skills/detection-engineering/OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "ingest-databricks-audit-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
PRODUCT_NAME = "cloud-ai-security-skills"
OUTPUT_FORMATS = ("ocsf", "native")

API_ACTIVITY_CLASS_UID = 6003
API_ACTIVITY_CLASS_NAME = "API Activity"
API_ACTIVITY_CATEGORY_UID = 6
API_ACTIVITY_CATEGORY_NAME = "Application Activity"
API_ACTIVITY_CREATE = 1
API_ACTIVITY_READ = 2
API_ACTIVITY_UPDATE = 3

SEVERITY_INFORMATIONAL = 1
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

# Databricks HTTP status codes < 400 are successes; the audit log records the
# API response's status code verbatim.
_SUCCESS_MAX_STATUS = 400


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def parse_ts_ms(value: Any) -> int:
    """Parse ``timestamp`` (epoch ms/seconds or ISO-8601 string) to epoch ms."""
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


def _get(record: dict[str, Any], *names: str) -> Any:
    """Case/shape-tolerant lookup: accept camelCase (log delivery) or
    snake_case (system table) spellings for the same field."""
    for name in names:
        if name in record:
            return record[name]
    lowered = {str(key).lower(): value for key, value in record.items()}
    for name in names:
        key = name.lower()
        if key in lowered:
            return lowered[key]
    return None


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a value that may be a dict or a JSON-encoded string to a dict."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _maybe_json(value: Any) -> Any:
    """Databricks audit ``requestParams`` values arrive as strings, sometimes
    carrying stringified JSON (e.g. ``init_scripts``). Parse those to their
    native shape; leave plain scalars untouched."""
    if isinstance(value, str):
        text = value.strip()
        if text[:1] in ("[", "{"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


def _rp_str(params: dict[str, Any], *names: str) -> str:
    for name in names:
        if name in params and params[name] is not None:
            return str(params[name]).strip()
    lowered = {str(k).lower(): v for k, v in params.items()}
    for name in names:
        key = name.lower()
        if key in lowered and lowered[key] is not None:
            return str(lowered[key]).strip()
    return ""


def _rp_int(params: dict[str, Any], *names: str) -> int | None:
    raw = _rp_str(params, *names)
    if raw == "":
        return None
    try:
        return int(raw)
    except ValueError:
        try:
            return int(float(raw))
        except ValueError:
            return None


def _status_id(status_code: Any) -> int:
    if status_code is None or status_code == "":
        return STATUS_SUCCESS
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return STATUS_SUCCESS
    return STATUS_SUCCESS if code < _SUCCESS_MAX_STATUS else STATUS_FAILURE


# --- Per-operation block builders ----------------------------------------
#
# Each builder maps a Databricks audit record's requestParams / response.result
# to the `unmapped.databricks.*` block the downstream detector reads. All take
# (request_params, response_result, workspace_id).

BlockBuilder = Callable[[dict[str, Any], dict[str, Any], str], dict[str, Any]]


def _cluster_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    # Databricks clusters/create returns the cluster_id in response.result;
    # clusters/edit carries it in requestParams. Accept either.
    cluster_id = _rp_str(rp, "cluster_id") or _rp_str(rr, "cluster_id")
    cluster_name = _rp_str(rp, "cluster_name")
    raw_scripts = _maybe_json(_get(rp, "init_scripts"))
    init_scripts: list[dict[str, Any]] = []
    if isinstance(raw_scripts, list):
        init_scripts = [item for item in raw_scripts if isinstance(item, dict)]
    config: dict[str, Any] = {}
    if cluster_id:
        config["cluster_id"] = cluster_id
    if cluster_name:
        config["cluster_name"] = cluster_name
    config["init_scripts"] = init_scripts
    return {"workspace_id": ws, "cluster_config": config}


def _secret_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    return {
        "workspace_id": ws,
        "secret_scope": _rp_str(rp, "scope", "secret_scope"),
        "secret_key": _rp_str(rp, "key", "secret_key"),
    }


def _mlflow_download_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    block: dict[str, Any] = {
        "workspace_id": ws,
        "model_name": _rp_str(rp, "name", "registered_model_name", "model_name"),
    }
    version = _rp_str(rp, "version", "model_version")
    if version:
        block["model_version"] = version
    return block


def _mlflow_transition_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    block = _mlflow_download_block(rp, rr, ws)
    stage = _rp_str(rp, "stage", "target_stage")
    if stage:
        block["target_stage"] = stage
    target_ws = _rp_str(rp, "target_workspace_id")
    if target_ws:
        block["target_workspace_id"] = target_ws
    return block


def _token_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    token_info = _as_dict(rr.get("tokenInfo") or rr.get("token_info"))
    token_id = (
        _rp_str(token_info, "tokenId", "token_id")
        or _rp_str(rp, "token_id", "tokenId")
        or _rp_str(rr, "token_id", "tokenId")
    )
    block: dict[str, Any] = {"workspace_id": ws}
    if token_id:
        block["token_id"] = token_id
    comment = _rp_str(rp, "comment")
    if comment:
        block["comment"] = comment
    lifetime = _rp_int(rp, "lifetime_seconds", "lifetimeSeconds")
    if lifetime is not None:
        block["lifetime_seconds"] = lifetime
    return block


def _recipient_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    name = _rp_str(rp, "name", "recipient_name")
    # Databricks Delta Sharing: authentication_type == TOKEN denotes an
    # open/external (token-based) recipient; DATABRICKS is workspace-to-workspace.
    auth = _rp_str(rp, "authentication_type", "auth_type").upper()
    explicit = _rp_str(rp, "type").upper()
    if explicit:
        rtype = explicit
    elif auth == "TOKEN":
        rtype = "EXTERNAL"
    elif auth:
        rtype = "DATABRICKS"
    else:
        rtype = ""
    recipient: dict[str, Any] = {}
    if name:
        recipient["id"] = name
    if rtype:
        recipient["type"] = rtype
    return {"workspace_id": ws, "recipient": recipient}


def _split_recipients(raw: Any) -> list[str]:
    value = _maybe_json(raw)
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _share_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    share: dict[str, Any] = {}
    name = _rp_str(rp, "name", "share_name")
    if name:
        share["name"] = name
    recipients = _split_recipients(_get(rp, "recipients"))
    if recipients:
        share["recipients"] = recipients
    return {"workspace_id": ws, "share": share}


def _grantee_dict(value: str) -> dict[str, Any]:
    grantee: dict[str, Any] = {}
    if value:
        grantee["uid"] = value
        if "@" in value:
            grantee["email_addr"] = value
    return grantee


def _set_admin_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    grantee = _rp_str(rp, "targetUserName", "target_user_name", "targetUserId", "endpointName")
    return {"workspace_id": ws, "grantee": _grantee_dict(grantee)}


def _group_block(rp: dict[str, Any], rr: dict[str, Any], ws: str) -> dict[str, Any]:
    group = _rp_str(rp, "group_name", "groupName", "parentName", "targetGroupName")
    grantee = _rp_str(rp, "targetUserName", "target_user_name", "userName", "user_name")
    block: dict[str, Any] = {"workspace_id": ws}
    if group:
        block["group_name"] = group
    block["grantee"] = _grantee_dict(grantee)
    return block


# --- Operation registry ---------------------------------------------------
#
# Keyed by (service_name.lower(), action_name.lower()); values give the
# canonical (api.operation, api.service.name, block-builder). The canonical
# operation string is exactly what the downstream detect-databricks-* rule
# anchors on — the downstream anchors use PascalCase for the Unity Catalog
# Delta-Sharing verbs and a `tokens/create` spelling for PAT issuance, so the
# registry normalizes the vendor-native action name to that contract rather
# than a naive `service.action` join. See REFERENCES.md for the source action
# names.


class OperationSpec:
    __slots__ = ("operation", "service_name", "builder", "activity_id")

    def __init__(
        self, operation: str, service_name: str, builder: BlockBuilder, activity_id: int = API_ACTIVITY_CREATE
    ) -> None:
        self.operation = operation
        self.service_name = service_name
        self.builder = builder
        self.activity_id = activity_id


OPERATION_REGISTRY: dict[tuple[str, str], OperationSpec] = {
    ("clusters", "create"): OperationSpec("clusters.create", "databricks.clusters", _cluster_block, API_ACTIVITY_CREATE),
    ("clusters", "edit"): OperationSpec("clusters.edit", "databricks.clusters", _cluster_block, API_ACTIVITY_UPDATE),
    ("secrets", "getsecret"): OperationSpec(
        "secrets.getSecret", "databricks.secrets", _secret_block, API_ACTIVITY_READ
    ),
    ("mlflowmodelregistry", "getmodelversiondownloaduri"): OperationSpec(
        "mlflow.getModelVersionDownloadUri", "databricks.mlflow", _mlflow_download_block, API_ACTIVITY_READ
    ),
    ("mlflow", "getmodelversiondownloaduri"): OperationSpec(
        "mlflow.getModelVersionDownloadUri", "databricks.mlflow", _mlflow_download_block, API_ACTIVITY_READ
    ),
    ("mlflowmodelregistry", "transitionmodelversionstage"): OperationSpec(
        "mlflow.transitionModelVersionStage", "databricks.mlflow", _mlflow_transition_block, API_ACTIVITY_UPDATE
    ),
    ("mlflow", "transitionmodelversionstage"): OperationSpec(
        "mlflow.transitionModelVersionStage", "databricks.mlflow", _mlflow_transition_block, API_ACTIVITY_UPDATE
    ),
    ("accounts", "generatedbtoken"): OperationSpec(
        "tokens/create", "databricks.token-management", _token_block, API_ACTIVITY_CREATE
    ),
    ("tokenmanagement", "createtoken"): OperationSpec(
        "tokens/create", "databricks.token-management", _token_block, API_ACTIVITY_CREATE
    ),
    ("unitycatalog", "createrecipient"): OperationSpec(
        "unityCatalog.CreateRecipient", "databricks.unity-catalog", _recipient_block, API_ACTIVITY_CREATE
    ),
    ("unitycatalog", "updaterecipient"): OperationSpec(
        "unityCatalog.UpdateRecipient", "databricks.unity-catalog", _recipient_block, API_ACTIVITY_UPDATE
    ),
    ("unitycatalog", "createshare"): OperationSpec(
        "unityCatalog.CreateShare", "databricks.unity-catalog", _share_block, API_ACTIVITY_CREATE
    ),
    ("unitycatalog", "updateshare"): OperationSpec(
        "unityCatalog.UpdateShare", "databricks.unity-catalog", _share_block, API_ACTIVITY_UPDATE
    ),
    ("accounts", "setadmin"): OperationSpec(
        "accounts.setAdmin", "databricks.iam", _set_admin_block, API_ACTIVITY_UPDATE
    ),
    ("accounts", "addusertogroup"): OperationSpec(
        "iam.addUserToGroup", "databricks.iam", _group_block, API_ACTIVITY_CREATE
    ),
    ("accounts", "addprincipaltogroup"): OperationSpec(
        "iam.addUserToGroup", "databricks.iam", _group_block, API_ACTIVITY_CREATE
    ),
    ("iam", "addusertogroup"): OperationSpec("iam.addUserToGroup", "databricks.iam", _group_block, API_ACTIVITY_CREATE),
}


def _service_action(record: dict[str, Any]) -> tuple[str, str]:
    service = str(_get(record, "serviceName", "service_name") or "").strip()
    action = str(_get(record, "actionName", "action_name") or "").strip()
    return service, action


def _request_params(record: dict[str, Any]) -> dict[str, Any]:
    return _as_dict(_get(record, "requestParams", "request_params"))


def _response(record: dict[str, Any]) -> dict[str, Any]:
    return _as_dict(_get(record, "response"))


def _workspace_id(record: dict[str, Any]) -> str:
    raw = _get(record, "workspaceId", "workspace_id")
    return str(raw).strip() if raw is not None else ""


def _record_uid(record: dict[str, Any]) -> str:
    raw = _get(record, "requestId", "request_id", "eventId", "event_id")
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    service, action = _service_action(record)
    ts = parse_ts_ms(_get(record, "timestamp"))
    return f"{service}.{action}:{ts}"


def _actor(record: dict[str, Any]) -> dict[str, Any]:
    identity = _as_dict(_get(record, "userIdentity", "user_identity"))
    email = str(identity.get("email") or identity.get("subjectName") or "").strip()
    if not email:
        # Some records carry the principal at the top level.
        email = str(_get(record, "userName", "user_name") or "").strip()
    user: dict[str, Any] = {}
    if email:
        user["uid"] = email
        user["name"] = email
        if "@" in email:
            user["email_addr"] = email
            user["type"] = "User"
        else:
            # A UUID / service-principal id has no `@`.
            user["type"] = "Service"
    else:
        user["type"] = "User"
    return {"user": user}


def derive_operation(record: dict[str, Any]) -> tuple[OperationSpec, dict[str, Any]] | None:
    """Resolve a Databricks audit record to (OperationSpec, unmapped.databricks
    block) or None when the (serviceName, actionName) pair is not relevant to
    any shipped databricks detector."""
    service, action = _service_action(record)
    if not service or not action:
        return None
    spec = OPERATION_REGISTRY.get((service.lower(), action.lower()))
    if spec is None:
        return None
    rp = _request_params(record)
    rr = _as_dict(_response(record).get("result"))
    ws = _workspace_id(record)
    block = spec.builder(rp, rr, ws)
    return spec, block


def _status_from_record(record: dict[str, Any]) -> int:
    status_code = _get(_response(record), "statusCode", "status_code")
    return _status_id(status_code)


def _build_ocsf(
    record: dict[str, Any], spec: OperationSpec, block: dict[str, Any]
) -> dict[str, Any]:
    uid = _record_uid(record)
    event: dict[str, Any] = {
        "activity_id": spec.activity_id,
        "category_uid": API_ACTIVITY_CATEGORY_UID,
        "category_name": API_ACTIVITY_CATEGORY_NAME,
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": API_ACTIVITY_CLASS_NAME,
        "type_uid": API_ACTIVITY_CLASS_UID * 100 + spec.activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": _status_from_record(record),
        "time": parse_ts_ms(_get(record, "timestamp")),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": uid,
            "product": {
                "name": PRODUCT_NAME,
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
        },
        "actor": _actor(record),
        "api": {"operation": spec.operation, "service": {"name": spec.service_name}},
    }
    src_ip = str(_get(record, "sourceIPAddress", "source_ip_address") or "").strip()
    if src_ip:
        event["src_endpoint"] = {"ip": src_ip}
    event["unmapped"] = {"databricks": block}
    return event


def _build_native(
    record: dict[str, Any], spec: OperationSpec, block: dict[str, Any]
) -> dict[str, Any]:
    uid = _record_uid(record)
    status_id = _status_from_record(record)
    native: dict[str, Any] = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "api_activity",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "provider": "Databricks",
        "event_uid": uid,
        "time_ms": parse_ts_ms(_get(record, "timestamp")),
        "status_id": status_id,
        "status": "success" if status_id == STATUS_SUCCESS else "failure",
        "operation": spec.operation,
        "service": spec.service_name,
        "actor": _actor(record),
        "unmapped": {"databricks": block},
    }
    src_ip = str(_get(record, "sourceIPAddress", "source_ip_address") or "").strip()
    if src_ip:
        native["src_endpoint"] = {"ip": src_ip}
    return native


def iter_raw_rows(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    """Yield audit-record dicts from NDJSON lines or a single JSON array."""
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
        rows = whole.get("rows") or whole.get("data") or whole.get("records")
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

    for record in iter_raw_rows(stream):
        if not isinstance(record, dict):
            continue
        try:
            derived = derive_operation(record)
        except Exception as exc:  # defensive: never crash on one bad record
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="parse_error",
                message=f"skipping record: parse error: {exc}",
                error=str(exc),
                event_uid=_record_uid(record),
            )
            continue
        if derived is None:
            if skipped_counts is not None:
                service, action = _service_action(record)
                key = f"{service}.{action}".strip(".") or "other"
                skipped_counts[key] = skipped_counts.get(key, 0) + 1
            continue
        spec, block = derived
        if output_format == "native":
            yield _build_native(record, spec, block)
        else:
            yield _build_ocsf(record, spec, block)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert Databricks audit-log records to OCSF 1.8 API Activity (6003) or native JSONL."
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
            f"{sum(skipped_counts.values())} irrelevant record(s) skipped"
        ),
        emitted=emitted,
        skipped=sum(skipped_counts.values()),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
