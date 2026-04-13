# Agent Instructions

> This file is the canonical repo-level contract for AI agents loading this
> repository (Claude Code, Cursor, Codex, Cortex, Windsurf, or any other
> AGENTS.md-aware or MCP-capable assistant). It is intentionally cross-agent.
> Use `CLAUDE.md` for Claude-specific project memory, and use each
> `skills/<layer>/<skill>/SKILL.md` for the actual skill contract.

## Repository at a glance

Skills are organised into layered categories. See [`skills/README.md`](skills/README.md) for the full catalog.

**`ingestion/`** (raw source → OCSF)
- `ingest-cloudtrail-ocsf`
- `ingest-vpc-flow-logs-ocsf`
- `ingest-vpc-flow-logs-gcp-ocsf`
- `ingest-nsg-flow-logs-azure-ocsf`
- `ingest-guardduty-ocsf`
- `ingest-security-hub-ocsf`
- `ingest-gcp-scc-ocsf`
- `ingest-azure-defender-for-cloud-ocsf`
- `ingest-gcp-audit-ocsf`
- `ingest-azure-activity-ocsf`
- `ingest-k8s-audit-ocsf`
- `ingest-mcp-proxy-ocsf`

**`detection/`** (OCSF → OCSF Detection Finding 2004 + MITRE)
- `detect-mcp-tool-drift`
- `detect-privilege-escalation-k8s`
- `detect-sensitive-secret-read-k8s`
- `detect-lateral-movement`

**`evaluation/`** (read-only posture / benchmark checks)
- `cspm-aws-cis-benchmark`
- `cspm-gcp-cis-benchmark`
- `cspm-azure-cis-benchmark`
- `k8s-security-benchmark`
- `container-security`
- `model-serving-security`
- `gpu-cluster-security`
- `discover-environment`

**`view/`** (OCSF export / rendering)
- `convert-ocsf-to-sarif`
- `convert-ocsf-to-mermaid-attack-flow`

**`remediation/`** (active fix workflows, HITL-gated, dual-audited)
- `iam-departures-remediation`

Compose via stdin/stdout pipes. The shared wire contract remains pinned in
[`skills/detection-engineering/OCSF_CONTRACT.md`](skills/detection-engineering/OCSF_CONTRACT.md).

## Which file to read

| File | Scope | When to use it |
|---|---|---|
| `README.md` | public overview | orient to repo purpose, modes, and safety model |
| `AGENTS.md` | cross-agent repo contract | before any agent edits or runs skills |
| `CLAUDE.md` | Claude-only memory | when Claude Code needs project memory and defaults |
| `skills/<layer>/<skill>/SKILL.md` | individual skill contract | before running or editing a specific skill |
| `skills/<layer>/<skill>/REFERENCES.md` | official references only | when verifying APIs, schemas, frameworks, or guardrails |

## Hard rules for agents

These rules are enforced in code, IAM, and infra. They are not optional:

1. **Read-only by default.** Treat any skill whose SKILL.md says `read-only` as exactly that. Never compose it into a flow that mutates cloud state.
2. **Dry-run first.** Every remediation worker accepts `dry_run=True`. Use it when planning, exploring, or generating examples. Only set `dry_run=False` after the user has explicitly confirmed and the action is inside an authorised maintenance window.
3. **Respect the deny list.** The IAM worker's role denies `iam:*` on `root`, `break-glass-*`, `emergency-*`, and any `:role/*` ARN. Do not propose workarounds.
4. **Respect the grace period.** The IAM departures grace period is a *human-in-the-loop* mechanism, not a delay. Do not set it to 0 or skip it without an authorisation document.
5. **Never bypass EventBridge.** All Step Function executions go through the `S3 Object Created → EventBridge → SFN` path. Do not call `states:StartExecution` directly — that bypasses the audit trail.
6. **Never write to the audit table by hand.** The `iam-remediation-audit` DynamoDB table is written exclusively by the worker Lambdas. Manual writes break the closed-loop verification.
7. **No new IAM grants.** Do not edit `iam_policies/` or any role policy to broaden permissions. Each role is least-privilege by design.
8. **No telemetry.** Nothing in this repo phones home. Do not add SDK clients to external services unless the user explicitly asks for them, and even then keep the egress inside the customer's VPC.

## Execution and approval model

| Mode | What changes | What does not change |
|---|---|---|
| **CLI / just-in-time** | operator or agent invokes the script directly | the skill contract, output format, and guardrails |
| **CI** | the workflow drives the skill | the skill contract, output format, and guardrails |
| **Persistent / serverless** | a queue, runner, or workflow invokes the skill repeatedly | the skill contract, output format, and guardrails |
| **MCP** | the local wrapper exposes the skill as a tool | the skill contract, output format, and guardrails |

Approval rules:
- **read-only skills** do not need human approval to run
- **write-capable skills** must expose dry-run and blast-radius language
- **destructive actions** require human approval and an audit trail
- **incoming findings are untrusted input** until validated against the skill contract

## Secure coding expectations

- Validate all untrusted input before parsing, SQL construction, or cloud API calls.
- Prefer parameterized queries and safe identifier handling over string interpolation.
- Avoid generic subprocess wrappers or arbitrary shell passthrough.
- Fail closed on deprecated or unknown cloud API shapes unless the skill explicitly supports a migration window.
- Redact tokens, secrets, and credentials from logs and stderr.
- Treat transport security, auth scope, and trust boundaries as part of the skill contract, not operational trivia.

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
- Per-skill contract: `skills/<layer>/<skill-name>/SKILL.md`
- Agent-specific guidance and current integration gaps: [`docs/agent-integrations.md`](docs/agent-integrations.md)
- Architecture diagrams (closed loops): [`README.md`](README.md)
- Security model: [`SECURITY.md`](SECURITY.md)
