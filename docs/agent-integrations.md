# Agent Integrations

This repo is a good fit for coding agents because each skill is already packaged
as a compact contract: `SKILL.md`, implementation code, tests, and infrastructure.
This document explains how to use that structure with Claude-oriented tooling,
Codex CLI, and generic AGENTS.md-aware agents.

## What Exists Today

- Root-level [AGENTS.md](../AGENTS.md) for repo-wide instructions
- Skill-level `SKILL.md` files that explain when a skill should be used
- JSON, console, and SARIF outputs that are easy for agents and CI systems to consume

## What Does Not Exist Yet

- A native MCP server shipped by this repo
- Agent-callable tools generated directly from the skills
- Automated Claude/Codex wrappers around the benchmark and remediation flows

Document those gaps clearly. Do not describe the repo as MCP-native until a real
server or tool layer ships.

## Claude / Anthropic Usage

- Use the root `AGENTS.md` as the repo-level instruction file.
- Use each `SKILL.md` as the task-specific contract for the nearest skill directory.
- Treat the benchmark scripts as read-only assessment tools and the IAM departures
  automation as a controlled remediation workflow.

Example prompts:

- "Audit the AWS CIS skill and verify its checks against the official AWS docs."
- "Update the IAM departures docs to prefer Secrets Manager and preserve EventBridge as the trigger path."
- "Add regression tests for pagination in the AWS CIS benchmark skill."

## Codex CLI Usage

- Codex reads `AGENTS.md`, so keep repo-level commands and safety rules there.
- When working inside a skill, read that skill's `SKILL.md` before editing code.
- Use focused test commands for the touched skill instead of generic repo-wide commands when possible.

## Recommended MCP Setup

Until this repo ships its own MCP server, use generic tooling such as:

- filesystem access for repo reads and edits
- Git or GitHub integration for PR workflows
- cloud-vendor MCP tools only if they are explicitly configured in your environment

Example shape for a local MCP config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

Keep this external to the repo unless you are ready to support it as a real project contract.

## Recommended Next Step

If you want first-class Claude/Codex integration, the right next implementation is:

1. expose each skill as a callable tool behind a small MCP server
2. map inputs and outputs onto the existing skill contracts
3. keep remediation skills explicit about dry-run, approval boundaries, and audit outputs

## References

- AGENTS.md open format: https://agents.md/
- Anthropic skills guide: https://platform.claude.com/docs/en/build-with-claude/skills-guide?curius=1426
- Anthropic MCP docs: https://docs.anthropic.com/en/docs/mcp
