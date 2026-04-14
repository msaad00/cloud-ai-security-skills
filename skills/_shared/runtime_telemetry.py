from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from typing import Any


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_stderr_enabled() -> bool:
    return os.environ.get("SKILL_LOG_FORMAT") == "json" or os.environ.get("AGENT_TELEMETRY") == "1"


def emit_stderr_event(
    skill_name: str,
    *,
    level: str,
    event: str,
    message: str,
    **fields: Any,
) -> None:
    if _json_stderr_enabled():
        payload: dict[str, Any] = {
            "timestamp": _now_iso(),
            "skill": skill_name,
            "level": level,
            "event": event,
            "message": message,
        }
        for key, value in fields.items():
            if value is None:
                continue
            payload[key] = value
        sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")
        sys.stderr.flush()
        return

    sys.stderr.write(f"[{skill_name}] {message}\n")
    sys.stderr.flush()
