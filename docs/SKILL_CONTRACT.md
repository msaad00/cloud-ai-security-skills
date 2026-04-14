# Skill Contract

This document defines the minimum contract for a shipped skill in `cloud-ai-security-skills`.

The goal is to keep skills:

- easy for humans to review
- safe for agents to call
- grounded in official references
- deterministic enough to test and trust

## Required layout

Every shipped skill under `skills/<category>/<skill-name>/` must include:

- `SKILL.md`
- `src/`
- `tests/`
- `REFERENCES.md`

Optional:

- `infra/`
- `examples/`
- `RUNBOOK.md`

## Required metadata

`SKILL.md` must include YAML frontmatter with:

- `name`
- `description`
- `license`
- `approval_model`
- `execution_modes`
- `side_effects`
- `input_formats`
- `output_formats`

Rules:

- `name` must match `^[a-z0-9-]+$`
- `name` must be 64 characters or fewer
- `description` must clearly state when the skill should be used
- `description` must clearly state what the skill must not be used for
- `approval_model` must be one of:
  - `none`
  - `dry_run_required`
  - `human_required`
- `execution_modes` must be a comma-separated subset of:
  - `jit`
  - `ci`
  - `mcp`
  - `persistent`
- `side_effects` must be a comma-separated subset of:
  - `none`
  - `writes-cloud`
  - `writes-identity`
  - `writes-storage`
  - `writes-database`
  - `writes-audit`
- `side_effects: none` must appear by itself, never combined with write scopes
- read-only skills must set:
  - `approval_model: none`
  - `side_effects: none`
- write-capable skills must set:
  - `approval_model: human_required`
  - one or more explicit write scopes in `side_effects`
- `input_formats` must be a comma-separated subset of:
  - `raw`
  - `canonical`
  - `native`
  - `ocsf`
- `output_formats` must be a comma-separated subset of:
  - `native`
  - `ocsf`
  - `bridge`
- every skill must declare the formats it supports today, even if only one mode is implemented

## Required language

Each `SKILL.md` must contain both:

- `Use when`
- `Do NOT use`

This keeps routing explicit and guardrails visible for Claude, Codex, Cursor, Windsurf, Cortex Code CLI, and other MCP-aware agents.

## Required references

`REFERENCES.md` must point to the official documentation, schema, API, benchmark, or framework the skill relies on.

Examples:

- AWS / Azure / GCP official docs
- Kubernetes docs
- OCSF schema docs
- MITRE ATT&CK / MITRE ATLAS
- SARIF spec

## Required behavior

- read-only by default unless the skill is explicitly a remediation/write path
- no hidden side effects
- deterministic output where practical
- explicit input/output shape
- defensive parsing on untrusted input
- explicit human-in-the-loop and runtime-mode declaration in frontmatter so agents know when they must stop for approval

## Required validation and error handling

- validate every untrusted input boundary before calling a cloud API or parser
- fail closed on unknown or malformed data
- write machine-usable results to `stdout` and human debugging detail to `stderr`
- return non-zero exit codes on contract-breaking failures
- surface partial-data / skipped-record behavior explicitly rather than silently dropping it

## API drift and deprecation handling

- cite only official docs, schemas, APIs, or benchmarks in `REFERENCES.md`
- prefer stable SDKs and documented API versions over ad hoc REST calls
- pin dependencies at the repo level and update them in grouped batches
- add or update tests whenever a provider changes response shape, enum values, or required fields
- treat deprecated APIs as a compatibility event: document the replacement, add coverage for both shapes during migration, then remove the old path intentionally

## Required tests

- at least one test module under `tests/`
- golden fixtures where they make sense
- malformed input or failure-path coverage for parsers and converters
- regression coverage for provider-specific parsing quirks or deprecated/alternate response shapes

## CI enforcement

CI currently validates:

- required files exist
- `name` format is valid
- `Use when` and `Do NOT use` are present
- `approval_model`, `execution_modes`, and `side_effects` are present and valid
- `input_formats` and `output_formats` are present and valid
- read-only skills do not use subprocess/shell execution
- write-capable skills document and test dry-run behavior
- write-capable skills explicitly require human approval
- wildcard IAM / RBAC policy entries carry an explicit `WILDCARD_OK` justification

The contract will expand over time, but new CI rules should only be added when the current tree already satisfies them.
