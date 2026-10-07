from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "mcp-server" / "src"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


POLICY = _load("cloud_security_arg_policy_test", SRC / "arg_policy.py")
SERVER = _load("cloud_security_server_arg_policy_test", SRC / "server.py")


def _check(args: list[str], category: str = "ingestion", root: Path = REPO_ROOT) -> None:
    POLICY.check_args(args, category=category, root=root)


@pytest.mark.parametrize(
    "args",
    [
        ["--output", "/tmp/out.jsonl"],
        ["--output=/tmp/out.jsonl"],
        ["--output", "victim.rc"],
        ["--outp", "x"],
        ["--o=x"],
        ["-o", "/tmp/out.jsonl"],
        ["-o/tmp/out.jsonl"],
        ["--config", "conf.json"],
        ["--manifest", "m.jsonl"],
        ["--quarantine-file", "q.jsonl"],
        ["--policy-findings-output", "p.json"],
        ["--proc-root", "/proc"],
        ["--log-root", "/var/log"],
        ["--scan-paths", "a"],
    ],
)
def test_rejects_file_path_flags(args):
    with pytest.raises(POLICY.ArgPolicyError, match="not accepted over MCP"):
        _check(args)


@pytest.mark.parametrize(
    "args",
    [
        ["/etc/passwd"],
        ["../secrets.env"],
        ["./x.jsonl"],
        ["~/.aws/credentials"],
        [".env"],
        ["C:\\Windows\\win.ini"],
        ["README.md"],
        ["--", "/etc/passwd"],
        ["--pretty", "/etc/passwd"],
        ["--region", "../x"],
        [""],
    ],
)
def test_rejects_positional_paths(args):
    with pytest.raises(POLICY.ArgPolicyError, match="filesystem path"):
        _check(args)


@pytest.mark.parametrize(
    ("args", "category"),
    [
        ([], "ingestion"),
        (["--output-format", "native"], "ingestion"),
        (["--query", "SELECT a/b FROM t -- c"], "ingestion"),
        (["--key", "logs/2026/10/06/events.jsonl", "--bucket", "b"], "ingestion"),
        (["--region", "us-east-1", "--section", "storage", "--output", "json"], "evaluation"),
        (["--output=console"], "evaluation"),
        (["--dry-run"], "remediation"),
        (["-"], "detection"),
        (["aws"], "discovery"),
    ],
)
def test_allows_documented_args(args, category):
    _check(args, category=category)


@pytest.mark.parametrize(
    "args",
    [
        ["--output", "json"],
        ["--output", "/tmp/x"],
    ],
)
def test_output_format_values_only_for_evaluation(args):
    with pytest.raises(POLICY.ArgPolicyError):
        _check(args, category="ingestion")


def test_evaluation_output_must_be_a_format_choice():
    with pytest.raises(POLICY.ArgPolicyError):
        _check(["--output", "README.md"], category="evaluation")
    with pytest.raises(POLICY.ArgPolicyError):
        _check(["--output"], category="evaluation")


@pytest.mark.parametrize("token", ["--apply", "--appl", "--app", "--ap", "--apply=1", "--appl=yes"])
def test_apply_prefixes_are_detected(token):
    assert POLICY.is_apply_flag(token)


@pytest.mark.parametrize(
    "token", ["--approve-pod-kill", "--dry-run", "apply", "-a", "--", "--auto"]
)
def test_non_apply_tokens(token):
    assert not POLICY.is_apply_flag(token)


# -- Wrapper integration ----------------------------------------------------


class _FakeSkill:
    def __init__(self, *, read_only: bool, category: str, entrypoint: str | None) -> None:
        self.name = "fake-skill"
        self.category = category
        self.capability = "read-only" if read_only else "write-remediation"
        self.read_only = read_only
        self.approver_roles = ()
        self.min_approvers = None
        self.mcp_timeout_seconds = None
        self.entrypoint = None if entrypoint is None else Path(entrypoint)
        self.skill_dir = Path("/nonexistent/fake-skill")
        self.output_formats = ()


@pytest.mark.parametrize(
    ("category", "entrypoint"),
    [("remediation", "handler.py"), ("evaluation", "checks.py")],
)
@pytest.mark.parametrize("token", ["--appl", "--app", "--apply=1"])
def test_apply_abbreviation_is_not_safe(category, entrypoint, token):
    skill = _FakeSkill(read_only=False, category=category, entrypoint=entrypoint)
    assert SERVER._is_safe_write_invocation(skill, []) is True
    assert SERVER._is_safe_write_invocation(skill, [token]) is False


def test_dry_run_required_skills_reject_apply_prefix_even_with_dry_run():
    skill = _FakeSkill(read_only=False, category="output", entrypoint="sink.py")
    assert SERVER._is_safe_write_invocation(skill, ["--dry-run"]) is True
    assert SERVER._is_safe_write_invocation(skill, ["--dry"]) is False
    assert SERVER._is_safe_write_invocation(skill, ["--dry-run", "--appl"]) is False


def test_apply_abbreviation_requires_approval_context_for_checks():
    skill = _FakeSkill(read_only=False, category="evaluation", entrypoint="checks.py")
    skill.approver_roles = ("security_lead",)
    assert SERVER._requires_approval_context(skill, ["--appl"]) is True


def test_call_tool_rejects_path_args_before_spawn(monkeypatch):
    audit_events: list[dict[str, object]] = []
    monkeypatch.setattr(
        SERVER,
        "tool_map",
        lambda: {"fake-skill": _FakeSkill(read_only=True, category="ingestion", entrypoint=None)},
    )
    monkeypatch.setattr(SERVER, "_emit_audit_event", lambda event: audit_events.append(event))

    def _boom(*args, **kwargs):
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(SERVER.subprocess, "run", _boom)
    with pytest.raises(ValueError, match="not accepted over MCP"):
        SERVER._call_tool("fake-skill", {"args": ["--output", "/tmp/victim"]})
    assert audit_events[0]["result"] == "error"
    assert audit_events[0]["error_type"] == "ArgPolicyError"


def test_call_tool_rejects_typed_path_parameters(tmp_path):
    with pytest.raises(ValueError, match="filesystem path"):
        SERVER._call_tool("ingest-cloudtrail-ocsf", {"input_path": str(tmp_path / "x.jsonl")})


def test_real_ingest_cannot_truncate_or_read_files(tmp_path):
    victim = tmp_path / "victim.rc"
    victim.write_text("important\n")
    with pytest.raises(ValueError):
        SERVER._call_tool(
            "ingest-cloudtrail-ocsf", {"input": "", "args": ["--output", str(victim)]}
        )
    assert victim.read_text() == "important\n"
    with pytest.raises(ValueError):
        SERVER._call_tool("ingest-cloudtrail-ocsf", {"args": [str(victim)]})


def test_handle_request_returns_invalid_params_for_path_args():
    response = SERVER._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ingest-cloudtrail-ocsf", "arguments": {"args": ["/etc/passwd"]}},
        }
    )
    assert response is not None
    assert response["error"]["code"] == -32602
    assert "input" in response["error"]["message"]


def test_tool_schema_does_not_advertise_path_parameters():
    defs = {name: SERVER.tool_definition(spec) for name, spec in SERVER.tool_map().items()}
    for name, tool in defs.items():
        props = tool["inputSchema"]["properties"]
        assert "input_path" not in props, name
        assert "output_path" not in props, name
        for example in tool["inputSchema"].get("examples", []):
            assert "input_path" not in example, name
            assert "output_path" not in example, name
    assert defs["cspm-aws-cis-benchmark"]["inputSchema"]["properties"]["json_output"]


# -- Child env scrub ----------------------------------------------------------


def test_child_env_excludes_wrapper_secrets(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_AUDIT_HMAC_KEY", "k" * 40)
    monkeypatch.setenv("CLOUD_SECURITY_MCP_AUDIT_LOG", "/tmp/audit.jsonl")
    monkeypatch.setenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", "a,b")
    monkeypatch.setenv("CLOUD_SECURITY_SSE_BEARER_KEYS", "tok")
    monkeypatch.setenv("CLOUD_SECURITY_HTTP_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("CLOUD_SECURITY_VENDOR_NAME", "acme")
    env = SERVER._build_child_env()
    assert "CLOUD_SECURITY_AUDIT_HMAC_KEY" not in env
    assert "CLOUD_SECURITY_MCP_AUDIT_LOG" not in env
    assert "CLOUD_SECURITY_MCP_ALLOWED_SKILLS" not in env
    assert "CLOUD_SECURITY_SSE_BEARER_KEYS" not in env
    assert env["CLOUD_SECURITY_HTTP_MAX_ATTEMPTS"] == "3"
    assert env["CLOUD_SECURITY_VENDOR_NAME"] == "acme"


# -- Drift guard: every argparse flag a skill ships must be classified -------

# Flags whose value is never a local filesystem path (or that take no value).
_NON_PATH_FLAGS = frozenset(
    {
        "--apply",
        "--approve-node-drain",
        "--approve-pod-kill",
        "--auth-swap-window-ms",
        "--auto-remediate",
        "--bucket",
        "--compression-type",
        "--confirm",
        "--control",
        "--dry-run",
        "--emit-policy-findings",
        "--expression",
        "--fenced",
        "--framework",
        "--hard-delete",
        "--hash-only",
        "--input-format",
        "--input-serialization",
        "--key",
        "--known-operator-principal",
        "--min-failures",
        "--mode",
        "--output-format",
        "--policy-findings-format",
        "--prefix",
        "--pretty",
        "--previous-hash",
        "--profile",
        "--project",
        "--query",
        "--region",
        "--reverify",
        "--section",
        "--sensitive-pattern",
        "--snapshot-class",
        "--snapshot-volumes",
        "--source",
        "--subcategory",
        "--subscription-id",
        "--table",
        "--upload",
        "--window-ms",
    }
)


def _skill_argparse_flags() -> list[tuple[Path, str, ast.Call]]:
    found: list[tuple[Path, str, ast.Call]] = []
    for path in sorted((REPO_ROOT / "skills").glob("*/*/src/**/*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_argument"
            ):
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith("-"):
                        found.append((path, arg.value, node))
    return found


def test_every_skill_flag_is_classified_for_the_mcp_boundary():
    unclassified = sorted(
        {
            f"{path.relative_to(REPO_ROOT)}: {flag}"
            for path, flag, _ in _skill_argparse_flags()
            if flag.startswith("--")
            and flag not in _NON_PATH_FLAGS
            and flag not in POLICY.PATH_FLAGS
        }
    )
    assert unclassified == [], (
        "new CLI flag(s) must be classified: add path-valued flags to "
        "arg_policy.PATH_FLAGS, or non-path flags to _NON_PATH_FLAGS here"
    )


def test_short_flags_are_only_output_aliases():
    shorts = {flag for _, flag, _ in _skill_argparse_flags() if not flag.startswith("--")}
    assert shorts <= {"-o"}


def test_output_choices_only_exist_on_evaluation_format_flags():
    for path, flag, node in _skill_argparse_flags():
        if flag != "--output":
            continue
        choices = next((kw.value for kw in node.keywords if kw.arg == "choices"), None)
        category = path.relative_to(REPO_ROOT / "skills").parts[0]
        if choices is None:
            assert category != "evaluation", path
            continue
        assert category == "evaluation", path
        assert set(ast.literal_eval(choices)) <= POLICY.FORMAT_OUTPUT_VALUES, path


def test_free_text_flag_does_not_swallow_a_following_path_flag():
    with pytest.raises(POLICY.ArgPolicyError):
        _check(["--query", "--output=/tmp/x"])


@pytest.mark.parametrize(
    ("skill", "payload"),
    [
        ("container-security", '{"containers": []}'),
        ("k8s-security-benchmark", "pods: []\n"),
        ("model-serving-security", '{"endpoints": []}'),
        ("gpu-cluster-security", "nodes: []\n"),
    ],
)
def test_config_benchmarks_read_config_from_input(skill, payload):
    import json

    result = SERVER._call_tool(skill, {"input": payload, "args": ["--output", "json"]})
    structured = result["structuredContent"]
    # Benchmarks exit 1 when a critical/high check fails; that is a result,
    # not a crash. The config must have been parsed from stdin either way.
    assert structured["exit_code"] in (0, 1), structured["stderr"]
    findings = json.loads(structured["stdout"])
    assert isinstance(findings, list) and findings
    assert all("check_id" in f for f in findings)


_NO_ABBREV_LAYERS = ("remediation", "evaluation", "output", "discovery", "view")


def test_write_capable_layers_disable_argparse_abbreviation():
    missing: list[str] = []
    for layer in _NO_ABBREV_LAYERS:
        for path in sorted((REPO_ROOT / "skills" / layer).glob("*/src/**/*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and getattr(node.func, "attr", getattr(node.func, "id", "")) == "ArgumentParser"
                ):
                    continue
                kw = {k.arg: k.value for k in node.keywords}
                value = kw.get("allow_abbrev")
                if not (isinstance(value, ast.Constant) and value.value is False):
                    missing.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert missing == []


def test_remediation_handler_rejects_abbreviated_apply():
    import subprocess

    handler = (
        REPO_ROOT / "skills" / "remediation" / "remediate-okta-session-kill" / "src" / "handler.py"
    )
    result = subprocess.run(
        [sys.executable, str(handler), "--appl"],
        input="",
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 2
    assert "unrecognized arguments: --appl" in result.stderr
