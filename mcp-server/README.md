# MCP Server

Thin MCP wrapper for `cloud-ai-security-skills`.

This server does not replace the existing skills model. It auto-discovers
`skills/*/*/SKILL.md`, resolves each supported skill to its existing Python
entrypoint, and exposes those skills as MCP tools for Claude Code, Codex,
Cursor, Windsurf, Cortex Code CLI, and other MCP clients.

Supported entrypoints today are fixed repo-owned Python surfaces:
`src/ingest.py`, `src/detect.py`, `src/convert.py`, `src/checks.py`,
`src/discover.py`, `src/handler.py`, and `src/sink.py`.

Design rules:

- no arbitrary shell execution
- no generic "run anything" tool
- no hidden runtime install path
- fixed local repo-owned entrypoints only
- direct CLI usage of skills stays unchanged

Argument boundary (`src/arg_policy.py`):

- payloads go through `input` (stdin); callers cannot point a skill at the
  host filesystem
- path-valued flags are rejected, including argparse prefix abbreviations
  and `=value` forms: `--output`/`-o`, `--config`, `--manifest`,
  `--quarantine-file`, `--policy-findings-output`, `--scan-paths`,
  `--proc-root`, `--log-root`; evaluation `checks.py` keeps
  `--output console|json`, which is a render switch
- positional args that look like a path (contain `/` or `\`, start with `.`
  or `~`, or name an existing file relative to the repo root) are rejected;
  `-` is allowed
- typed schema parameters that map to paths (`input_path`, `output_path`)
  are no longer advertised in `tools/list` and are rejected the same way
- `container-security`, `k8s-security-benchmark`, `model-serving-security`,
  and `gpu-cluster-security` read their JSON/YAML config from stdin when the
  `config` path is omitted, so pass it as `input`
- rejections return JSON-RPC `-32602` and are audited with
  `error_type: ArgPolicyError`; the skill is never spawned

Child environment:

- skills get a fixed allowlist of process vars plus `CLOUD_SECURITY_*`
  settings, minus wrapper-only values: `CLOUD_SECURITY_AUDIT_HMAC_KEY`,
  anything under `CLOUD_SECURITY_MCP_*`, and any name containing `BEARER` or
  `HMAC`

Remediation parity:

- standalone remediation skills with a single `src/handler.py` entrypoint are
  exposed over MCP
- `iam-departures-{aws,gcp,azure-entra}` are also exposed via top-level
  `src/handler.py` shims (see #411) — one MCP tool per cloud, not one tool for
  the full multi-Lambda orchestration
- those tools stay dry-run/re-verify only at the wrapper boundary; the MCP
  wrapper rejects `--apply`, any abbreviation of it (`--appl`), and
  `--apply=...`; write-capable layers also set `allow_abbrev=False` on their
  parsers

Audit behavior:

- the wrapper emits one JSON audit line per resolved tool call
- the audit record contract lives in [../docs/MCP_AUDIT_CONTRACT.md](../docs/MCP_AUDIT_CONTRACT.md)
- a configured `CLOUD_SECURITY_AUDIT_HMAC_KEY` must be at least 32 bytes and
  not the `please-set-me` template placeholder; otherwise the stdio server
  and the SSE listener exit with status 2 before serving
- wrapper diagnostics stay on `stderr`; wrapped skill output stays on `stdout`
- every audit event records the resolved `timeout_seconds` so operators can tell from the log whether a call was governed by the default, a per-skill override, or an env override
- every call also gets a wrapper-generated `correlation_id` that is recorded in
  the MCP audit event and forwarded into the skill as `SKILL_CORRELATION_ID`
  so structured `stderr` can be joined back to the audited tool invocation
- the wrapper accepts optional `_caller_context` and `_approval_context`
  objects so a trusted client wrapper can propagate identity, ticket, and
  approver metadata into both MCP audit logs and the spawned skill process

Approval behavior:

- write-capable tools stay in safe mode at the wrapper boundary:
  generic write tools still require `--dry-run`, while dry-run-default
  `handler.py` and `checks.py` entrypoints are allowed as long as `--apply`
  is absent
- if a skill declares `approver_roles`, the caller must provide
  `_approval_context`
- if a skill declares `min_approvers > 1`, `_approval_context` must carry that
  many distinct approvers via `approver_ids` or `approver_emails`
- the wrapper forwards those values into the subprocess as
  `SKILL_APPROVER_ID`, `SKILL_APPROVER_EMAIL`, `SKILL_APPROVER_IDS`,
  `SKILL_APPROVER_EMAILS`, and `SKILL_APPROVAL_TICKET`

Timeout behavior:

Each tool call runs the skill in a subprocess with a hard timeout.

- Default: `60` seconds (from `DEFAULT_TIMEOUT_SECONDS` in `src/server.py`).
- Per-skill override: a skill's `SKILL.md` frontmatter may declare `mcp_timeout_seconds: <N>` (range `1`–`900`) when the skill's realistic runtime exceeds the default. No shipped skill sets this today; the field is opt-in and defaults to the global value.
- Operator override: setting the `CLOUD_SECURITY_MCP_TIMEOUT_SECONDS` environment variable wins over both, so on-call can widen or tighten the window without editing any `SKILL.md`.

Resolution order, highest wins: env override > per-skill value > default.

Skill allowlist:

Operators can constrain which skills are exposed as MCP tools via the
`CLOUD_SECURITY_MCP_ALLOWED_SKILLS` environment variable — a comma-separated
list of skill names (e.g. `cspm-aws-cis-benchmark,detect-lateral-movement`).
When set, unlisted skills are filtered out of both `tools/list` and
`tools/call`, so a client (or an agent loop) cannot invoke a skill that
isn't on the allowlist. Unset / empty = all discovered skills exposed
(default). This is the per-client least-privilege gate referenced in
`docs/integrations/*.md`.

Trusted client wrappers can also pass `_caller_context.allowed_skills` on
`tools/list` and `tools/call`. That caller scope is intersected with the
operator allowlist, so process-level policy still wins and a caller can only
narrow its own visible/callable skill set. Set
`CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS=1` to fail closed unless each
request supplies `_caller_context.allowed_skills`; calls without that scope see
no tools and cannot invoke any tool.

Run locally:

```bash
python3 mcp-server/src/server.py
```

Project-scoped Claude Code config lives in the repo root at [`.mcp.json`](../.mcp.json).

Transports:

- `stdio` is the default local MCP transport.
- `sse` / streamable HTTP is opt-in for networked clients and requires bearer
  keys plus the dependency groups documented in
  [`docs/MCP_TRANSPORT.md`](../docs/MCP_TRANSPORT.md).
