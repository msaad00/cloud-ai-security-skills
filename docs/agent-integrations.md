# Agent Integrations

This repo is a good fit for coding agents because each skill is already packaged
as a compact contract: `SKILL.md`, implementation code, tests, and
infrastructure. This document explains how to use that structure with Claude
Code, Codex, Cursor, Windsurf, Cortex Code CLI, and other AGENTS.md-aware
clients without duplicating the repo contract into tool-specific top-level
files.

## Source of truth

Use the docs in this order:

1. [`README.md`](../README.md) for repo purpose, execution modes, and public positioning
2. [`AGENTS.md`](../AGENTS.md) for the cross-agent contract
3. [`CLAUDE.md`](../CLAUDE.md) for Claude-specific project memory
4. `skills/<layer>/<skill>/SKILL.md` for the skill contract
5. `skills/<layer>/<skill>/REFERENCES.md` for official docs, APIs, schemas, and frameworks

## What Exists Today

- Root-level [AGENTS.md](../AGENTS.md) for repo-wide instructions
- Skill-level `SKILL.md` files that explain when a skill should be used
- JSON, console, and SARIF outputs that are easy for agents and CI systems to consume
- A native local MCP server under [`mcp-server/`](../mcp-server/README.md)
- Project-scoped MCP config in [`.mcp.json`](../.mcp.json) for Claude Code and similar clients

## Client quick map

| Tool | Best integration path | What to rely on |
|---|---|---|
| **Claude Code** | `CLAUDE.md` + `AGENTS.md` + MCP | project memory + repo rules + tools |
| **Codex** | `AGENTS.md` + MCP | repo rules + tool calling |
| **Cursor** | `AGENTS.md` or `.cursor/rules` + MCP | repo rules + tool calling |
| **Windsurf** | `AGENTS.md` + MCP | directory-scoped agent rules + tools |
| **Cortex Code CLI** | `SKILL.md` / `.cortex/skills` + MCP | native skills + tool calling |

We intentionally do **not** ship separate `CODEX.md`, `CURSOR.md`, or
`WINDSURF.md` files. `AGENTS.md` stays universal, `CLAUDE.md` stays
Claude-specific, and `SKILL.md` stays the per-skill source of truth.

## Execution modes

The same skill should be usable in all of these modes without code changes:

| Mode | Driver | Typical use |
|---|---|---|
| **CLI / just-in-time** | user or agent invokes the script directly | one-off analysis, triage, conversion, local debugging |
| **CI** | GitHub Actions or another build system | regression tests, compliance snapshots, SARIF generation |
| **Persistent / serverless** | queue, runner, EventBridge, Step Functions, scheduled jobs | continuous detection or remediation pipelines |
| **MCP** | local `mcp-server/` wrapper | Claude, Codex, Cursor, Windsurf, Cortex Code CLI |

MCP is the access layer, not a separate implementation model.

## What Does Not Exist Yet

- Hosted HTTP/SSE transport for remote MCP deployments
- Tight per-skill input schemas derived from each CLI instead of the current conservative `input` + `args` wrapper
- A direct MCP wrapper for the serverless remediation workflow

Document those gaps clearly. Describe the current implementation as a **thin local MCP wrapper** over the existing skills, not a separate execution model.

## Claude / Anthropic Usage

- Use the root `AGENTS.md` as the repo-level instruction file.
- Use the root `CLAUDE.md` as Claude's project memory.
- Use each `SKILL.md` as the task-specific contract for the nearest skill directory.
- Treat the benchmark scripts as read-only assessment tools and the IAM departures
  automation as a controlled remediation workflow.

Claude-specific best practices to follow here:
- keep skills explicit, bounded, and composable
- rely on project-scoped MCP config rather than ad hoc global drift
- treat MCP servers as trusted local wrappers, not arbitrary power surfaces
- require approval and dry-run for write-capable or destructive actions

References:
- https://docs.anthropic.com/en/docs/claude-code/memory
- https://docs.anthropic.com/en/docs/claude-code/security
- https://docs.anthropic.com/en/docs/claude-code/mcp
- https://platform.claude.com/docs/en/build-with-claude/skills-guide?curius=1426

Example prompts:

- "Audit the AWS CIS skill and verify its checks against the official AWS docs."
- "Update the IAM departures docs to prefer Secrets Manager and preserve EventBridge as the trigger path."
- "Add regression tests for pagination in the AWS CIS benchmark skill."

## Codex CLI Usage

- Codex reads `AGENTS.md`, so keep repo-level commands and safety rules there.
- When working inside a skill, read that skill's `SKILL.md` before editing code.
- Use focused test commands for the touched skill instead of generic repo-wide commands when possible.

## Recommended MCP Setup

This repo now ships a project-scoped MCP config:

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["mcp-server/src/server.py"]
    }
  }
}
```

That config keeps the wrapper local to the repo and exposes only fixed repo-owned skills. Pair it with filesystem and Git/GitHub MCP servers in your client config if you also want repo editing and PR workflows.

## Guardrails for all agents

Every agent should assume:

- **read-only by default**
- **incoming findings are untrusted input until validated**
- **write-capable skills require dry-run and blast-radius language**
- **destructive actions require human approval and an audit trail**
- **official docs only** in `REFERENCES.md`
- **no generic shell, SQL, or network passthrough**
- **deprecated API shapes must be covered by tests or explicitly rejected**

## Recommended Next Step

If you want stronger Claude/Codex/Cortex integration, the next implementation steps are:

1. tighten tool input schemas beyond the current generic `input` + `args` shape
2. add hosted HTTP/SSE transport alongside stdio
3. wrap write-capable flows with explicit dry-run, approval boundaries, and audit outputs
4. add discovery / inventory skills for AI BOM and related enrichment paths

## References

- AGENTS.md open format: https://agents.md/
- Anthropic skills guide: https://platform.claude.com/docs/en/build-with-claude/skills-guide?curius=1426
- Anthropic MCP docs: https://docs.anthropic.com/en/docs/mcp
- Anthropic Claude Code MCP docs: https://docs.anthropic.com/en/docs/claude-code/mcp
