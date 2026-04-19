# MCP Server

Thin stdio MCP wrapper for `cloud-ai-security-skills`.

This server does not replace the existing skills model. It auto-discovers
`skills/*/*/SKILL.md`, resolves each supported skill to its existing Python
entrypoint, and exposes those skills as MCP tools for Claude Code, Codex,
Cursor, Windsurf, Cortex Code CLI, and other MCP clients.

Design rules:

- no arbitrary shell execution
- no generic "run anything" tool
- no hidden runtime install path
- fixed local repo-owned entrypoints only
- direct CLI usage of skills stays unchanged

Audit behavior:

- the wrapper emits one JSON audit line per resolved tool call
- the audit record contract lives in [../docs/MCP_AUDIT_CONTRACT.md](../docs/MCP_AUDIT_CONTRACT.md)
- wrapper diagnostics stay on `stderr`; wrapped skill output stays on `stdout`
- every audit event records the resolved `timeout_seconds` so operators can tell from the log whether a call was governed by the default, a per-skill override, or an env override
- every call also gets a wrapper-generated `correlation_id` that is recorded in
  the MCP audit event and forwarded into the skill as `SKILL_CORRELATION_ID`
  so structured `stderr` can be joined back to the audited tool invocation

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

Run locally:

```bash
python3 mcp-server/src/server.py
```

Project-scoped Claude Code config lives in the repo root at [`.mcp.json`](../.mcp.json).
