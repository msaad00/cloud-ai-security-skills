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

Run locally:

```bash
python3 mcp-server/src/server.py
```

Project-scoped Claude Code config lives in the repo root at [`.mcp.json`](../.mcp.json).
