"""FastAPI receiver — wires HTTP POST → atomic ingest skill → sink fan-out.

Single endpoint shape: `POST /webhook/<skill-name>`. Defaults are
default-deny so a fresh deployment cannot route any payload until
`WEBHOOK_ALLOWED_SKILLS` opts a skill in, and an allowlisted skill still
needs an HMAC secret or bearer token. Authentication runs before routing
and every auth failure is the same `401 unauthorized`, so an
unauthenticated caller cannot tell which skills exist or are allowlisted;
the specific reason goes to the audit record only. Bodies above
`WEBHOOK_MAX_BODY_BYTES` (default 1 MiB) are refused with 413.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# FastAPI is intentionally an extras-only dependency. Importing this
# module without FastAPI installed surfaces a clear error so operators
# know which extras to add.
try:  # pragma: no cover - exercised only when extra is missing
    from fastapi import FastAPI, HTTPException, Request, Response
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "runners.webhook-receiver requires `fastapi`. Install with "
        "`uv sync --group dev --extra webhook` (or pin fastapi in your "
        "deployment image)."
    ) from exc

CURRENT_DIR = Path(__file__).resolve().parent
MCP_SRC = CURRENT_DIR.parents[2] / "mcp-server" / "src"
for _path in (CURRENT_DIR, MCP_SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from arg_policy import is_wrapper_only_env  # noqa: E402  pylint: disable=wrong-import-position
from auth import (  # noqa: E402  pylint: disable=wrong-import-position
    ReplayCache,
    auth_configured_for,
    hmac_secrets,
    timestamp_tolerance_seconds,
    verify_bearer,
    verify_hmac,
)
from router import REPO_ROOT, resolve  # noqa: E402  pylint: disable=wrong-import-position
from sinks import (  # noqa: E402  pylint: disable=wrong-import-position
    SinkResult,
    fan_out,
    new_correlation_id,
)

MAX_BODY_ENV = "WEBHOOK_MAX_BODY_BYTES"
DEFAULT_MAX_BODY_BYTES = 1024 * 1024


def _max_body_bytes() -> int:
    raw = (os.environ.get(MAX_BODY_ENV) or "").strip()
    if not raw:
        return DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value <= 0:
        raise ValueError(f"{MAX_BODY_ENV} must be a positive integer, got {raw!r}")
    return value


# Validate configuration at import so a misconfigured deploy refuses to start.
hmac_secrets()
timestamp_tolerance_seconds()
MAX_BODY_BYTES = _max_body_bytes()
REPLAY_CACHE = ReplayCache()


class _PayloadTooLarge(Exception):
    pass


async def _read_body(request: Request) -> bytes:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _PayloadTooLarge
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise _PayloadTooLarge
    return bytes(body)


app = FastAPI(
    title="cloud-ai-security-skills · webhook receiver",
    docs_url=None,
    redoc_url=None,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _emit_audit(event: dict[str, Any]) -> None:
    """Best-effort audit emit — same shape as the MCP wrapper.

    stderr is the always-on sink; if `CLOUD_SECURITY_MCP_AUDIT_LOG` is
    set the receiver appends one line per resolved request to that
    file with `os.fsync()`.
    """
    line = json.dumps(event, sort_keys=True) + "\n"
    sys.stderr.write(line)
    sys.stderr.flush()
    log_path = (os.environ.get("CLOUD_SECURITY_MCP_AUDIT_LOG") or "").strip()
    if not log_path:
        return
    try:
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:  # pragma: no cover - audit best-effort
        pass


def _sink_results_to_dict(results: list[SinkResult]) -> list[dict[str, Any]]:
    return [
        {
            "target": r.target,
            "ok": r.ok,
            "exit_code": r.exit_code,
            "correlation_id": r.correlation_id,
            "error": r.error,
        }
        for r in results
    ]


def _authenticate(
    skill_name: str,
    headers: dict[str, str],
    body: bytes,
    audit_event: dict[str, Any],
) -> str:
    """Return the failure reason, or "" when the request is authenticated."""
    if not auth_configured_for(skill_name):
        return "auth_not_configured"
    hmac_result = verify_hmac(skill_name, headers, body)
    if not hmac_result.ok:
        return hmac_result.reason
    bearer_result = verify_bearer(headers)
    if not bearer_result.ok:
        return bearer_result.reason
    if hmac_result.replay_key:
        audit_event["hmac_scheme"] = "legacy_body_only" if hmac_result.legacy else "timestamped"
        if not REPLAY_CACHE.check_and_store(
            hmac_result.replay_key,
            expires_at=hmac_result.replay_expires_at,
            now=int(time.time()),
        ):
            return "replayed_request"
    return ""


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "webhook-receiver"}


@app.post("/webhook/{skill_name}")
async def webhook(skill_name: str, request: Request) -> Response:
    started = time.monotonic()
    correlation_id = new_correlation_id()
    headers = {k.lower(): v for k, v in request.headers.items()}
    audit_event: dict[str, Any] = {
        "event": "webhook_request",
        "timestamp": _now_iso(),
        "correlation_id": correlation_id,
        "skill": skill_name,
        "payload_sha256": "",
        "payload_length": 0,
        "result": "pending",
    }

    try:
        try:
            body = await _read_body(request)
        except _PayloadTooLarge:
            audit_event["result"] = "error"
            audit_event["error_type"] = "payload_too_large"
            raise HTTPException(status_code=413, detail="payload_too_large") from None
        audit_event["payload_sha256"] = hashlib.sha256(body).hexdigest() if body else ""
        audit_event["payload_length"] = len(body)

        # 1) Auth before routing, so 401 never depends on whether the route
        # exists. Fail closed when nothing is configured for this name.
        auth_failure = _authenticate(skill_name, headers, body, audit_event)
        if auth_failure:
            audit_event["result"] = "error"
            audit_event["error_type"] = auth_failure
            raise HTTPException(status_code=401, detail="unauthorized")

        # 2) Routing — closed-set: unknown / wrong-category / not allowlisted.
        resolution = resolve(skill_name)
        if not resolution.found:
            audit_event["result"] = "error"
            audit_event["error_type"] = "skill_not_found"
            audit_event["error_message"] = resolution.reason
            raise HTTPException(status_code=404, detail=resolution.reason)
        if not resolution.allowed:
            audit_event["result"] = "error"
            audit_event["error_type"] = "skill_not_allowed"
            audit_event["error_message"] = resolution.reason
            raise HTTPException(status_code=403, detail=resolution.reason)

        # 3) Skill execution — feed the raw body to stdin, capture OCSF JSONL.
        skill = resolution.skill
        assert skill is not None and skill.entrypoint is not None
        completed = subprocess.run(
            [sys.executable, str(skill.entrypoint)],
            input=body,
            capture_output=True,
            cwd=REPO_ROOT,
            env={
                **{
                    k: v
                    for k, v in os.environ.items()
                    if k.startswith("CLOUD_SECURITY_") and not is_wrapper_only_env(k)
                },
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                "PYTHONUNBUFFERED": "1",
                "SKILL_CORRELATION_ID": correlation_id,
            },
            check=False,
            timeout=120,
        )
        audit_event["skill_exit_code"] = completed.returncode
        audit_event["stdout_length"] = len(completed.stdout)
        if completed.returncode != 0:
            audit_event["result"] = "error"
            audit_event["error_type"] = "skill_failed"
            audit_event["error_message"] = (completed.stderr or b"").decode(
                "utf-8", errors="replace"
            )[-512:]
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "skill_failed",
                    "exit_code": completed.returncode,
                    "stderr": (completed.stderr or b"").decode("utf-8", errors="replace")[-512:],
                },
            )

        # 4) Sink fan-out — best effort, surface per-target results.
        sink_results = fan_out(completed.stdout, correlation_id)
        audit_event["sink_results"] = _sink_results_to_dict(sink_results)
        audit_event["result"] = "success"
        return Response(
            content=json.dumps(
                {
                    "correlation_id": correlation_id,
                    "skill": skill_name,
                    "skill_exit_code": completed.returncode,
                    "stdout_length": len(completed.stdout),
                    "sink_results": _sink_results_to_dict(sink_results),
                }
            ),
            media_type="application/json",
            status_code=200,
        )
    except HTTPException:
        raise
    except subprocess.TimeoutExpired as exc:
        audit_event["result"] = "error"
        audit_event["error_type"] = "skill_timeout"
        audit_event["error_message"] = f"skill timed out after {exc.timeout}s"
        raise HTTPException(status_code=504, detail="skill timed out") from exc
    except Exception as exc:  # pragma: no cover - last-resort safety net
        audit_event["result"] = "error"
        audit_event["error_type"] = type(exc).__name__
        audit_event["error_message"] = str(exc)
        raise
    finally:
        audit_event["duration_ms"] = int((time.monotonic() - started) * 1000)
        _emit_audit(audit_event)
