"""Detect MCP tool schema drift mid-session (OCSF input → OCSF Detection Finding).

Reads OCSF 1.8 Application Activity events (class 6002) produced by the sibling
ingest-mcp-proxy-ocsf skill, tracks tool fingerprints per (session, tool name),
and emits one OCSF Detection Finding (class 2004) per drift event.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "detect-mcp-tool-drift"
OCSF_VERSION = "1.8.0"

# Detection Finding (2004) — the replacement for the deprecated
# Security Finding (2001) since OCSF 1.1.0.
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1  # 1 Create · 2 Update · 3 Close · 99 Other (OCSF 1.8)
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

# Severity: High — drift is a strong signal and actionable immediately.
SEVERITY_HIGH = 4

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0001"
MITRE_TACTIC_NAME = "Initial Access"
MITRE_TECHNIQUE_UID = "T1195.001"
MITRE_TECHNIQUE_NAME = "Supply Chain Compromise: Compromise Software Supply Chain"


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------


def _is_tools_list_response_with_fingerprint(event: dict[str, Any]) -> bool:
    """True iff the event is a tools/list response with a populated tool fingerprint."""
    if event.get("class_uid") != 6002:
        return False
    mcp = event.get("mcp") or {}
    if mcp.get("method") != "tools/list" or mcp.get("direction") != "response":
        return False
    tool = mcp.get("tool") or {}
    return bool(tool.get("name")) and bool(tool.get("fingerprint"))


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def _build_finding(
    session_uid: str,
    tool_name: str,
    before_event: dict[str, Any],
    after_event: dict[str, Any],
) -> dict[str, Any]:
    """Produce one OCSF 1.8 Detection Finding (class 2004) describing a single drift.

    Field layout follows OCSF 1.8:
      - attacks[] lives INSIDE finding_info (not at event root — that was the
        pre-1.1 Security Finding layout).
      - status_id is recommended, not required.
      - type_uid = class_uid * 100 + activity_id  (200401).
    """
    before_tool = before_event["mcp"]["tool"]
    after_tool = after_event["mcp"]["tool"]
    before_fp = before_tool["fingerprint"]
    after_fp = after_tool["fingerprint"]

    # Deterministic ID so re-running on the same input is idempotent.
    uid = f"det-mcp-drift-{session_uid}-{tool_name}-{before_fp.split(':')[-1][:8]}-{after_fp.split(':')[-1][:8]}"

    title = "MCP tool schema drift detected mid-session"
    desc = (
        f"Tool '{tool_name}' changed fingerprint between tools/list responses in session "
        f"'{session_uid}'. Before: {before_fp}; after: {after_fp}. This is the MCP "
        f"tool-poisoning / rug-pull pattern (MITRE T1195.001). The agent may have already "
        f"called this tool under the previous schema and will trust the new one."
    )

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": 1,  # 1 Success — recommended field, the detector ran cleanly
        "time": after_event.get("time") or _now_ms(),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "cloud-security",
                "vendor_name": "msaad00/cloud-security",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "mcp", "supply-chain", "tool-drift"],
        },
        "finding_info": {
            "uid": uid,
            "title": title,
            "desc": desc,
            "types": ["mcp-tool-drift"],
            "first_seen_time": before_event.get("time"),
            "last_seen_time": after_event.get("time"),
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": MITRE_TACTIC_NAME, "uid": MITRE_TACTIC_UID},
                    "technique": {"name": MITRE_TECHNIQUE_NAME, "uid": MITRE_TECHNIQUE_UID},
                }
            ],
        },
        "observables": [
            {"name": "session.uid", "type": "Other", "value": session_uid},
            {"name": "tool.name", "type": "Other", "value": tool_name},
            {"name": "tool.before_fingerprint", "type": "Fingerprint", "value": before_fp},
            {"name": "tool.after_fingerprint", "type": "Fingerprint", "value": after_fp},
        ],
        "evidence": {
            "events_observed": 2,
            "before_event_time": before_event.get("time"),
            "after_event_time": after_event.get("time"),
            # Intentionally empty — the contract says raw events stay in storage,
            # not inside the finding. A follow-up PR will wire a raw_uri.
            "raw_events": [],
        },
    }


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------


def detect(events: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """Walk events in order; yield a finding per (session, tool) drift.

    State is minimal: one last-seen fingerprint per (session, tool name). We also
    cache the event that produced the last fingerprint so the finding can cite
    exact evidence.
    """
    # (session_uid, tool_name) -> (last_fingerprint, last_event)
    state: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}

    # Materialise and stable-sort by time so out-of-order JSONL still works.
    listed = [e for e in events if _is_tools_list_response_with_fingerprint(e)]
    listed.sort(key=lambda e: (e.get("mcp", {}).get("session_uid", ""), e.get("time", 0)))

    for event in listed:
        mcp = event["mcp"]
        session_uid = mcp.get("session_uid", "sess-unknown")
        tool = mcp["tool"]
        tool_name = tool["name"]
        fingerprint = tool["fingerprint"]

        key = (session_uid, tool_name)
        prior = state.get(key)
        if prior is None:
            state[key] = (fingerprint, event)
            continue

        prior_fp, prior_event = prior
        if prior_fp == fingerprint:
            # Republished with same fingerprint — no drift.
            continue

        yield _build_finding(session_uid, tool_name, prior_event, event)
        # Update state so we only raise ONCE per distinct transition.
        # A subsequent re-drift will produce a new finding because the "before"
        # fingerprint has moved forward.
        state[key] = (fingerprint, event)


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
    parser = argparse.ArgumentParser(description="Detect MCP tool schema drift from OCSF events.")
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
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
