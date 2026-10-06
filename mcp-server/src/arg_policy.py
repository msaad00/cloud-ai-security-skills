"""Caller-input policy for the wrapper boundary: argv and child env.

MCP callers (an LLM agent, or whoever can reach the SSE listener) must not
be able to point a skill at the wrapper host's filesystem. Payloads travel
through the `input` field; CLI args are limited to non-path flags. The
policy runs on the final argv (typed schema parameters included) before any
subprocess is spawned.

Skills use argparse with prefix abbreviation enabled in some layers, so a
flag is matched by prefix too: `--outp` reaches `--output`, `--appl`
reaches `--apply`.
"""

from __future__ import annotations

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from audit_sink import AUDIT_HMAC_KEY_ENV  # noqa: E402

# Every argparse flag in skills/*/*/src whose value is a local file or
# directory. `mcp-server/tests/test_arg_policy.py` fails when a skill adds a
# flag that is in neither this set nor the test's non-path allowlist.
PATH_FLAGS = frozenset(
    {
        "--config",
        "--log-root",
        "--manifest",
        "--output",
        "--policy-findings-output",
        "--proc-root",
        "--quarantine-file",
        "--scan-paths",
    }
)

# Evaluation `checks.py` entrypoints use `--output {console,json}` as a
# render switch, not a path.
FORMAT_OUTPUT_VALUES = frozenset({"console", "json"})

# Flags whose value is free text that may legitimately contain `/`
# (SQL, S3 keys and prefixes, regexes). Never local paths.
FREE_TEXT_VALUE_FLAGS = frozenset(
    {"--expression", "--key", "--prefix", "--query", "--sensitive-pattern"}
)

APPLY_FLAG = "--apply"


class ArgPolicyError(ValueError):
    pass


def _abbreviates(name: str, flag: str) -> bool:
    return len(name) > 2 and flag.startswith(name)


def is_apply_flag(token: str) -> bool:
    """True for `--apply`, any argparse abbreviation of it, and `=value` forms."""
    if not token.startswith("--"):
        return False
    return _abbreviates(token.split("=", 1)[0], APPLY_FLAG)


def _looks_like_path(token: str, root: Path) -> bool:
    if token == "-":
        return False
    if not token or "/" in token or "\\" in token or token.startswith((".", "~")):
        return True
    try:
        return (root / token).exists()
    except (OSError, ValueError):
        return True


def _path_flag_error(name: str) -> ArgPolicyError:
    return ArgPolicyError(
        f"`{name}` takes a filesystem path and is not accepted over MCP; "
        "pass the payload through `input` and read results from the tool response"
    )


def _positional_error(token: str) -> ArgPolicyError:
    return ArgPolicyError(
        f"argument {token!r} looks like a filesystem path; file paths are not accepted "
        "over MCP, pass the payload through `input`"
    )


def _check_output_value(value: str | None) -> None:
    if value not in FORMAT_OUTPUT_VALUES:
        raise ArgPolicyError(
            f"`--output` only accepts {sorted(FORMAT_OUTPUT_VALUES)} over MCP; "
            "file outputs are not accepted"
        )


def check_args(args: list[str], *, category: str, root: Path) -> None:
    """Raise `ArgPolicyError` when `args` would make a skill read or write a
    local file chosen by the caller. `root` is the subprocess cwd, used to
    catch bare relative filenames."""
    pending_value_for: str | None = None
    positional_only = False
    for token in args:
        if positional_only:
            if _looks_like_path(token, root):
                raise _positional_error(token)
            continue
        if pending_value_for is not None:
            flag, pending_value_for = pending_value_for, None
            if flag == "--output":
                _check_output_value(token)
                continue
            if not token.startswith("-") or token == "-":
                continue
        if token == "--":
            positional_only = True
            continue
        if token.startswith("--"):
            name, has_value, value = token.partition("=")
            if any(_abbreviates(name, flag) for flag in PATH_FLAGS):
                if name != "--output" or category != "evaluation":
                    raise _path_flag_error(name)
                if has_value:
                    _check_output_value(value)
                else:
                    pending_value_for = name
            elif name in FREE_TEXT_VALUE_FLAGS and not has_value:
                pending_value_for = name
            continue
        if token.startswith("-o"):
            raise _path_flag_error("-o")
        if token.startswith("-") and token != "-":
            continue
        if _looks_like_path(token, root):
            raise _positional_error(token)
    if pending_value_for == "--output":
        _check_output_value(None)


def is_wrapper_only_env(key: str) -> bool:
    """Wrapper configuration and secrets that skill subprocesses never read
    (audit chain key, MCP/runner settings, bearer and HMAC material)."""
    return (
        key == AUDIT_HMAC_KEY_ENV
        or key.startswith("CLOUD_SECURITY_MCP_")
        or "BEARER" in key
        or "HMAC" in key
    )


def is_path_schema_property(prop_schema: dict[str, object]) -> bool:
    """True for typed `mcp_tool_schema.json` properties that map to a file
    path (positional input, or a path-valued flag)."""
    if prop_schema.get("x-cli-style") == "positional":
        return True
    flag = prop_schema.get("x-cli-flag")
    if not isinstance(flag, str) or flag not in PATH_FLAGS:
        return False
    return not (flag == "--output" and prop_schema.get("x-cli-value") in FORMAT_OUTPUT_VALUES)
