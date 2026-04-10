# Agent Instructions

> This file is the canonical entry point for AI agents loading this repository
> (Claude Code, Cursor, Codex, Cortex, Windsurf, or any other MCP-compatible
> assistant). It mirrors `CLAUDE.md` and links to the per-skill `SKILL.md`
> contracts.

## Repository at a glance

5 closed-loop cloud security skills:

| Skill | Mode | What it does |
|-------|------|--------------|
| `cspm-aws-cis-benchmark` | read-only | 18 CIS AWS Foundations v3.0 checks |
| `cspm-gcp-cis-benchmark` | read-only | 7 CIS GCP Foundations v3.0 checks |
| `cspm-azure-cis-benchmark` | read-only | 6 CIS Azure Foundations v2.1 checks |
| `iam-departures-remediation` | event-driven, audited | Multi-cloud IAM cleanup for departed employees |
| `vuln-remediation-pipeline` | gated by SLA + protected list | Auto-remediate supply chain vulns |

## Hard rules for agents

These rules are enforced in code, IAM, and infra. They are not optional:

1. **Read-only by default.** Treat any skill whose SKILL.md says `read-only` as exactly that. Never compose it into a flow that mutates cloud state.
2. **Dry-run first.** Every remediation worker accepts `dry_run=True`. Use it when planning, exploring, or generating examples. Only set `dry_run=False` after the user has explicitly confirmed and the action is inside an authorised maintenance window.
3. **Respect the deny list.** The IAM worker's role denies `iam:*` on `root`, `break-glass-*`, `emergency-*`, and any `:role/*` ARN. Do not propose workarounds.
4. **Respect the grace period.** The IAM departures grace period is a *human-in-the-loop* mechanism, not a delay. Do not set it to 0 or skip it without an authorisation document.
5. **Never bypass EventBridge.** All Step Function executions go through the `S3 Object Created → EventBridge → SFN` path. Do not call `states:StartExecution` directly — that bypasses the audit trail.
6. **Never write to the audit table by hand.** The `iam-remediation-audit` and `vuln-remediation-audit` DynamoDB tables are written exclusively by the worker Lambdas. Manual writes break the closed-loop verification.
7. **No new IAM grants.** Do not edit `iam_policies/` or any role policy to broaden permissions. Each role is least-privilege by design.
8. **No telemetry.** Nothing in this repo phones home. Do not add SDK clients to external services unless the user explicitly asks for them, and even then keep the egress inside the customer's VPC.

## How to use a skill

1. Read its `SKILL.md` (frontmatter + body) — that is the contract.
2. Read the `Security Guardrails` and `Remediation` sections.
3. If the skill has a `dry_run` flag, call it with `dry_run=True` first and show the steps.
4. Only proceed with destructive actions after user confirmation **and** the relevant audit/SLA checks pass.
5. After running, point the user at the audit trail (`DynamoDB` + `S3 evidence` + `warehouse ingest-back`) so they can verify the closed loop.

## Failure handling

- Lambda async failure → SQS DLQ (`iam-departures-dlq`).
- Step Function `FAILED` / `TIMED_OUT` / `ABORTED` → SNS `iam-departures-alerts` topic.
- Re-drive a stuck execution by re-emitting an `Object Created` event for the manifest. The pipeline is idempotent.

If you see a remediation step that succeeded but no audit row, treat it as a failure and surface the discrepancy to the user.

## Where to read more

- Full guardrails and rationale: [`CLAUDE.md`](CLAUDE.md)
- Per-skill contract: `skills/<skill-name>/SKILL.md`
- Architecture diagrams (closed loops): [`README.md`](README.md)
- Security model: [`SECURITY.md`](SECURITY.md)
