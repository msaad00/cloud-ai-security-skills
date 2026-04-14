from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from tool_registry import build_command, repo_root, tool_definition, tool_map  # noqa: E402

SERVER_NAME = "cloud-ai-security-skills"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2025-06-18"
DEFAULT_TIMEOUT_SECONDS = 60


def _error_response(request_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def _result_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _read_message(stream) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        name, value = line.decode("utf-8").split(":", 1)
        headers[name.strip().lower()] = value.strip()

    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    payload = stream.read(length)
    return json.loads(payload.decode("utf-8"))


def _write_message(stream, message: dict[str, Any]) -> None:
    payload = json.dumps(message).encode("utf-8")
    stream.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("utf-8"))
    stream.write(payload)
    stream.flush()


def _validate_args(raw_args: Any) -> list[str]:
    if raw_args is None:
        return []
    if not isinstance(raw_args, list) or not all(isinstance(arg, str) for arg in raw_args):
        raise ValueError("`args` must be an array of strings")
    return raw_args


def _validate_input(raw_input: Any) -> str:
    if raw_input is None:
        return ""
    if not isinstance(raw_input, str):
        raise ValueError("`input` must be a string")
    return raw_input


def _validate_output_format(raw_output_format: Any) -> str | None:
    if raw_output_format is None:
        return None
    if not isinstance(raw_output_format, str):
        raise ValueError("`output_format` must be a string")
    return raw_output_format


def _validate_context(raw_context: Any, field_name: str) -> dict[str, Any] | None:
    if raw_context is None:
        return None
    if not isinstance(raw_context, dict):
        raise ValueError(f"`{field_name}` must be an object")
    validated: dict[str, Any] = {}
    for key, value in raw_context.items():
        if not isinstance(key, str):
            raise ValueError(f"`{field_name}` keys must be strings")
        if isinstance(value, str):
            validated[key] = value
            continue
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            validated[key] = value
            continue
        raise ValueError(f"`{field_name}.{key}` must be a string or array of strings")
    return validated


def _call_tool(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    tools = tool_map()
    if name not in tools:
        raise KeyError(f"unknown tool `{name}`")

    skill = tools[name]
    args = _validate_args((arguments or {}).get("args"))
    stdin_text = _validate_input((arguments or {}).get("input"))
    output_format = _validate_output_format((arguments or {}).get("output_format"))
    caller_context = _validate_context((arguments or {}).get("_caller_context"), "_caller_context")
    approval_context = _validate_context((arguments or {}).get("_approval_context"), "_approval_context")

    if not skill.read_only and "--dry-run" not in args:
        raise ValueError("write-capable tools must be called with `--dry-run`")
    if not skill.read_only and skill.approver_roles and approval_context is None:
        raise ValueError("write-capable tools with approver_roles require `_approval_context`")

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    if caller_context:
        if "user_id" in caller_context:
            env["SKILL_CALLER_ID"] = caller_context["user_id"]
        if "email" in caller_context:
            env["SKILL_CALLER_EMAIL"] = caller_context["email"]
        if "session_id" in caller_context:
            env["SKILL_SESSION_ID"] = caller_context["session_id"]
        if "roles" in caller_context:
            env["SKILL_CALLER_ROLES"] = ",".join(caller_context["roles"])
    if approval_context:
        if "approver_id" in approval_context:
            env["SKILL_APPROVER_ID"] = approval_context["approver_id"]
        if "approver_email" in approval_context:
            env["SKILL_APPROVER_EMAIL"] = approval_context["approver_email"]
        if "ticket_id" in approval_context:
            env["SKILL_APPROVAL_TICKET"] = approval_context["ticket_id"]
        if "approval_timestamp" in approval_context:
            env["SKILL_APPROVAL_TIMESTAMP"] = approval_context["approval_timestamp"]
    timeout_seconds = int(env.get("CLOUD_SECURITY_MCP_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    completed = subprocess.run(
        build_command(skill, args, output_format=output_format),
        input=stdin_text,
        text=True,
        capture_output=True,
        cwd=repo_root(),
        env=env,
        timeout=timeout_seconds,
        check=False,
    )

    output_text = completed.stdout or completed.stderr or ""
    result = {
        "content": [{"type": "text", "text": output_text}],
        "structuredContent": {
            "skill": skill.name,
            "category": skill.category,
            "capability": skill.capability,
            "output_format": output_format or "default",
            "caller_context_provided": caller_context is not None,
            "approval_context_provided": approval_context is not None,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "exit_code": completed.returncode,
        },
        "isError": completed.returncode != 0,
    }
    return result


def _handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return _result_response(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )

    if method == "ping":
        return _result_response(request_id, {})

    if method == "tools/list":
        tools = [tool_definition(skill) for skill in tool_map().values()]
        return _result_response(request_id, {"tools": tools})

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        if not isinstance(name, str):
            return _error_response(request_id, -32602, "`tools/call` requires a string `name`")
        try:
            return _result_response(request_id, _call_tool(name, params.get("arguments")))
        except KeyError as exc:
            return _error_response(request_id, -32601, str(exc))
        except ValueError as exc:
            return _error_response(request_id, -32602, str(exc))
        except subprocess.TimeoutExpired as exc:
            return _error_response(request_id, -32000, f"tool timed out after {exc.timeout}s")

    return _error_response(request_id, -32601, f"method not found: {method}")


def serve() -> int:
    while True:
        message = _read_message(sys.stdin.buffer)
        if message is None:
            return 0
        response = _handle_request(message)
        if response is not None:
            _write_message(sys.stdout.buffer, response)


if __name__ == "__main__":
    raise SystemExit(serve())
