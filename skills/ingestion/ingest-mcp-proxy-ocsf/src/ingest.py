"""Convert raw MCP proxy logs to canonical or OCSF Application Activity records.

Input:  JSONL as emitted by `agent-bom proxy --log-format jsonl`
Output: JSONL of OCSF 1.8 Application Activity events with the
        cloud_security_mcp custom profile.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.env import env_int  # noqa: E402
from skills._shared.identity import VENDOR_NAME  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402
from skills._shared.timestamps import (  # noqa: E402
    TimestampUnparseable,
    emit_timestamp_unparseable,
    require_ts_ms,
)

SKILL_NAME = "ingest-mcp-proxy-ocsf"
# Framework depth markers (coverage_summary.py)
# control_id="MCP01"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
MCP_PROFILE = "cloud_security_mcp"
OUTPUT_FORMATS = ("ocsf", "native")

# OCSF 1.8 Application Activity (6002) — unchanged from 1.3 for this class.
CLASS_UID = 6002
CLASS_NAME = "Application Activity"
CATEGORY_UID = 6
CATEGORY_NAME = "Application Activity"

# Activity enum (OCSF 1.8 Application Activity)
ACTIVITY_CREATE = 1  # a new record (e.g. tools/list response)
ACTIVITY_READ = 2  # a read-style call (e.g. tools/call request)
ACTIVITY_UNKNOWN = 0

# Opt-in content preservation. Off by default: tool schemas, sampling
# prompts, and message text can carry sensitive data, so the default output
# keeps only fingerprints. When on, only the fields the MCP content detectors
# read are kept, each capped at MAX_CHARS characters.
PRESERVE_CONTENT_ENV = "MCP_PRESERVE_CONTENT"
MAX_CHARS_ENV = "MCP_PRESERVE_CONTENT_MAX_CHARS"
DEFAULT_MAX_CHARS = 16384
_TRUTHY = {"1", "true", "yes", "on"}


def preserve_content_from_env() -> bool:
    return os.environ.get(PRESERVE_CONTENT_ENV, "").strip().lower() in _TRUTHY


# ---------------------------------------------------------------------------
# Fingerprinting — the cross-skill pivot point for tool drift detection
# ---------------------------------------------------------------------------


def tool_fingerprint(tool: dict[str, Any]) -> str:
    """Stable sha256 over (name, description, inputSchema, annotations).

    Any change to any of these fields is considered a tool drift event.
    Sorted keys ensure the same tool produces the same fingerprint regardless
    of dict ordering in the raw JSON.
    """
    canonical = json.dumps(
        {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "inputSchema": tool.get("inputSchema", {}),
            "annotations": tool.get("annotations", {}),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def input_schema_fingerprint(tool: dict[str, Any]) -> str:
    canonical = json.dumps(tool.get("inputSchema", {}), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# OCSF event builder
# ---------------------------------------------------------------------------


def _called_tool_name(raw: dict[str, Any]) -> str:
    params = raw.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    return name if isinstance(name, str) else ""


def _event_uid(raw: dict[str, Any], tool_name: str = "", tool_index: int | None = None) -> str:
    """Deterministic event id built only from identity fields.

    Raw ``params`` / ``body`` (tools/call arguments, prompts, tool output) are
    deliberately excluded: the other inputs appear in the output, so hashing
    content into an unkeyed digest would let a reader brute-force short or
    guessable values. The JSON-RPC ``id`` (when the proxy records it) and the
    tool name / position keep uids unique per emitted event.
    """
    return hashlib.sha256(
        json.dumps(
            {
                "timestamp": raw.get("timestamp", ""),
                "session_id": raw.get("session_id", "sess-unknown"),
                "method": raw.get("method", ""),
                "direction": raw.get("direction", ""),
                "jsonrpc_id": raw.get("id"),
                "tool_name": tool_name,
                "tool_index": tool_index,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _activity_name(activity_id: int) -> str:
    return {
        ACTIVITY_CREATE: "create",
        ACTIVITY_READ: "read",
        ACTIVITY_UNKNOWN: "unknown",
    }.get(activity_id, "unknown")


def _status_name(status_id: int) -> str:
    return {1: "success", 0: "unknown"}.get(status_id, "unknown")


def _build_canonical_event(
    raw: dict[str, Any], activity_id: int, event_uid: str | None = None
) -> dict[str, Any]:
    """Populate the stable repo-owned canonical activity shape."""
    if event_uid is None:
        event_uid = _event_uid(raw)
    return {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "application_activity",
        "source_skill": SKILL_NAME,
        "event_uid": event_uid,
        "provider": "MCP",
        "time_ms": require_ts_ms(raw.get("timestamp")),
        "activity_id": activity_id,
        "activity_name": _activity_name(activity_id),
        "severity": "informational",
        "severity_id": 1,
        "status": _status_name(1),
        "status_id": 1,
        "profile": MCP_PROFILE,
        "session_uid": raw.get("session_id", "sess-unknown"),
        "method": raw.get("method", "unknown"),
        "direction": raw.get("direction", "unknown"),
    }


# ---------------------------------------------------------------------------
# Opt-in content preservation
# ---------------------------------------------------------------------------


def _max_chars() -> int:
    return max(1, env_int(MAX_CHARS_ENV, DEFAULT_MAX_CHARS, skill_name=SKILL_NAME))


def _text_of(content: Any) -> str | None:
    """Flatten MCP sampling content to text; image/audio blocks are dropped."""
    if isinstance(content, str):
        return content
    blocks = content if isinstance(content, list) else [content]
    texts = [
        b["text"]
        for b in blocks
        if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
    ]
    return "\n".join(texts) if texts else None


def _preserved_unmapped(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Build `unmapped.mcp` with prompt/message text or tools/call response output."""
    params = raw.get("params")
    if not isinstance(params, dict):
        params = {}
    cap = _max_chars()
    truncated: list[str] = []

    def _capped(value: str, label: str) -> str:
        if len(value) > cap:
            truncated.append(label)
            return value[:cap]
        return value

    mcp: dict[str, Any] = {}
    system_prompt = params.get("systemPrompt")
    if isinstance(system_prompt, str) and system_prompt:
        mcp["prompt"] = _capped(system_prompt, "prompt")
    messages = params.get("messages")
    if isinstance(messages, list):
        kept: list[dict[str, str]] = []
        for i, msg in enumerate(messages):
            text = _text_of(msg.get("content")) if isinstance(msg, dict) else None
            label = f"request.params.messages[{i}].content"
            kept.append({"content": _capped(text, label)} if text else {})
        if any(kept):
            mcp["request"] = {"params": {"messages": kept}}
    body = raw.get("body")
    if raw.get("method") == "tools/call" and raw.get("direction") == "response" and body:
        if len(json.dumps(body, separators=(",", ":"))) > cap:
            mcp["response"] = {"body_omitted": "size_cap"}
        else:
            mcp["response"] = {"body": body}
    if not mcp:
        return None
    if truncated:
        mcp["truncated_fields"] = truncated
    return {"mcp": mcp}


def _preserve_input_schema(tool_out: dict[str, Any], tool: dict[str, Any]) -> None:
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return
    if len(json.dumps(schema, separators=(",", ":"))) > _max_chars():
        tool_out["input_schema_omitted"] = "size_cap"
    else:
        tool_out["input_schema"] = schema


def _render_ocsf_event(canonical: dict[str, Any]) -> dict[str, Any]:
    """Project the canonical activity shape into the pinned OCSF envelope."""
    event = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + canonical["activity_id"],
        "severity_id": canonical["severity_id"],
        "status_id": canonical["status_id"],
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "profiles": [MCP_PROFILE],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "mcp", "ingest"],
        },
        "mcp": {
            "session_uid": canonical["session_uid"],
            "method": canonical["method"],
            "direction": canonical["direction"],
        },
    }
    if canonical.get("tool"):
        event["mcp"]["tool"] = dict(canonical["tool"])
    if canonical.get("unmapped"):
        event["unmapped"] = canonical["unmapped"]
    return event


def _render_native_event(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["output_format"] = "native"
    return native


def _with_tool(
    canonical: dict[str, Any], tool: dict[str, Any], preserve_mcp_content: bool = False
) -> dict[str, Any]:
    event = dict(canonical)
    event["tool"] = {
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "input_schema_sha256": input_schema_fingerprint(tool),
        "fingerprint": tool_fingerprint(tool),
    }
    if preserve_mcp_content:
        _preserve_input_schema(event["tool"], tool)
    return event


def convert_event(
    raw: dict[str, Any],
    output_format: str = "ocsf",
    *,
    preserve_mcp_content: bool = False,
) -> Iterable[dict[str, Any]]:
    """Convert one raw proxy line into zero or more application activity events.

    - tools/list response -> one OCSF event per tool in the response (Create)
    - tools/call request  -> one OCSF event (Read) carrying the called tool's
      name so a detector can cross-reference the last known fingerprint for
      that tool in the same session.
    - Other methods/directions -> one OCSF event with no tool payload.

    With ``preserve_mcp_content`` (opt-in), tools/list events also carry
    ``mcp.tool.input_schema`` and requests carrying ``params.systemPrompt`` /
    ``params.messages`` (e.g. sampling/createMessage) carry their text under
    ``unmapped.mcp``, and tools/call responses carry their output under
    ``unmapped.mcp.response.body``. tools/call arguments are never preserved.

    Raw ``params`` / ``body`` are never emitted in either output format.
    """
    method = raw.get("method", "")
    direction = raw.get("direction", "")

    if method == "tools/list" and direction == "response":
        tools = (raw.get("body") or {}).get("tools") or []
        if not tools:
            canonical = _build_canonical_event(raw, ACTIVITY_CREATE)
            yield (
                _render_native_event(canonical)
                if output_format == "native"
                else _render_ocsf_event(canonical)
            )
            return
        for index, tool in enumerate(tools):
            name = tool.get("name", "") if isinstance(tool, dict) else ""
            uid = _event_uid(raw, name if isinstance(name, str) else "", index)
            canonical = _with_tool(
                _build_canonical_event(raw, ACTIVITY_CREATE, uid), tool, preserve_mcp_content
            )
            yield (
                _render_native_event(canonical)
                if output_format == "native"
                else _render_ocsf_event(canonical)
            )
        return

    if method == "tools/call" and direction == "request":
        called_name = _called_tool_name(raw)
        event = _build_canonical_event(raw, ACTIVITY_READ, _event_uid(raw, called_name))
        if called_name:
            # Do NOT populate a fingerprint here — this is a call, not a
            # declaration. The detector pairs the call to the last-seen
            # fingerprint in the same session.
            event["tool"] = {"name": called_name}
        yield (
            _render_native_event(event) if output_format == "native" else _render_ocsf_event(event)
        )
        return

    # Anything else — emit a base event so the downstream pipeline stays
    # aware of activity on the session.
    canonical = _build_canonical_event(raw, ACTIVITY_UNKNOWN)
    if preserve_mcp_content:
        unmapped = _preserved_unmapped(raw)
        if unmapped:
            canonical["unmapped"] = unmapped
    yield (
        _render_native_event(canonical)
        if output_format == "native"
        else _render_ocsf_event(canonical)
    )


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def _line_messages(parsed: Any, lineno: int) -> list[dict[str, Any]]:
    """Return the records on one line: the object itself, or the members of a
    JSON-RPC batch array (one level; nested arrays are not batches)."""
    if isinstance(parsed, dict):
        return [parsed]
    if not isinstance(parsed, list):
        print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)
        return []
    if not parsed:
        print(f"[{SKILL_NAME}] skipping line {lineno}: empty JSON-RPC batch", file=sys.stderr)
        return []
    members: list[dict[str, Any]] = []
    for index, member in enumerate(parsed):
        if isinstance(member, dict):
            members.append(member)
        else:
            print(
                f"[{SKILL_NAME}] skipping line {lineno} batch member {index}: not a JSON object",
                file=sys.stderr,
            )
    return members


def ingest(
    lines: Iterable[str],
    output_format: str = "ocsf",
    *,
    preserve_mcp_content: bool = False,
) -> Iterable[dict[str, Any]]:
    """Yield activity records for a stream of raw JSONL lines.

    A line holding a JSON array is a JSON-RPC batch: each object member is
    converted exactly as if it were its own line, under the same redaction
    rules.
    """
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    for lineno, line in enumerate(lines, start=1):
        if lineno == 1:
            line = line.removeprefix("﻿")
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {e}", file=sys.stderr)
            continue
        for raw in _line_messages(parsed, lineno):
            try:
                yield from convert_event(
                    raw, output_format=output_format, preserve_mcp_content=preserve_mcp_content
                )
            except TimestampUnparseable:
                emit_timestamp_unparseable(SKILL_NAME, record=lineno, line=lineno)
            except Exception as e:  # defence-in-depth — never crash the pipeline
                print(f"[{SKILL_NAME}] skipping line {lineno}: convert error: {e}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert raw MCP proxy JSONL to OCSF or native Application Activity JSONL."
    )
    parser.add_argument("input", nargs="?", help="Input JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF Application Activity (default) or the native canonical projection.",
    )
    parser.add_argument(
        "--preserve-mcp-content",
        action="store_true",
        help=(
            "Opt in to keeping tool inputSchema, sampling systemPrompt, and message text "
            f"(capped per field) so content detectors can fire. Also enabled by "
            f"{PRESERVE_CONTENT_ENV}=1. Off by default."
        ),
    )
    args = parser.parse_args(argv)
    preserve = args.preserve_mcp_content or preserve_content_from_env()
    if preserve:
        emit_stderr_event(
            SKILL_NAME,
            level="info",
            event="mcp_content_preserved",
            message=(
                "MCP content preservation is ON: tool schemas, sampling prompts, and "
                "message text are retained in output (capped per field)."
            ),
            max_chars=_max_chars(),
        )

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for event in ingest(
            in_stream, output_format=args.output_format, preserve_mcp_content=preserve
        ):
            out_stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
