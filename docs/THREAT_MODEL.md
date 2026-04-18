# Threat Model

This repo ships deterministic security skills, not a shared trusted runtime.
The threat model therefore focuses on:

- the skill contract
- the wrappers and runners that execute skills
- the credentials and sinks those paths can touch
- the trust boundaries between operators, agents, runtimes, and cloud APIs

This document is scenario-oriented. It is meant to answer the questions a
security reviewer or procurement reviewer will ask:

- what assets matter
- who the likely adversaries are
- what can go wrong
- what controls already exist
- what remains the operator's responsibility

Read next:

- [../SECURITY.md](../SECURITY.md)
- [../SECURITY_BAR.md](../SECURITY_BAR.md)
- [THREAT_MODEL_COVERAGE.md](THREAT_MODEL_COVERAGE.md)
- [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md)
- [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)
- [CREDENTIAL_PROVENANCE.md](CREDENTIAL_PROVENANCE.md)

## Scope

In scope:

- shipped skills under `skills/`
- runners under `runners/`
- the local MCP wrapper under `mcp-server/`
- CI, release, SBOM, and validation scripts under `.github/workflows/` and `scripts/`
- shipped sink and source adapters
- signed release artifacts and dependency metadata

Out of scope:

- customer cloud accounts, data lakes, and sinks beyond the repo-owned controls
- operator IAM, network, retention, and key-management policy outside the contracts documented here
- security posture of third-party SaaS or cloud vendors themselves

## System Model

The core product model is:

- stateless skills read from files, stdin, cloud APIs, or read-only source adapters
- skills emit deterministic results on stdout
- wrappers may schedule, gate, retry, dedupe, or persist those results
- write-capable paths are isolated to remediation skills, sinks, and runner edges

The repo does not assume one always-on daemon or a trusted central control plane.

## Assets

| Asset | Why it matters | Typical examples |
|---|---|---|
| Skill code and contracts | Defines behavior, permissions, and non-goals | `SKILL.md`, `src/`, `tests/`, validators |
| Caller and approver context | Proves who invoked a tool and who approved a write | MCP caller context, approval context, ticket references |
| Credentials and tokens | Gate access to cloud APIs, lakes, and sinks | workload identity, STS creds, cloud SDK default chains, sink credentials |
| Findings, evidence, and inventories | Security-relevant outputs that may trigger action or audit | OCSF findings, native findings, evidence JSON, AI BOM, graph snapshots |
| Audit trails and sink results | Prove what write paths did, where data landed, and whether dedupe occurred | remediation action logs, sink summaries, DDB/S3 audit rows |
| CI and release artifacts | Establish supply-chain integrity and upgrade trust | signed SBOM, release assets, coverage, validation output |
| MCP channel and wrappers | Mediate local tool execution and can widen or narrow trust | stdio MCP wrapper, runtime telemetry, tool registry |

## Trust Boundaries

| Boundary | What crosses it | Main concern |
|---|---|---|
| Operator or agent -> skill process | CLI args, stdin, env vars, file paths | untrusted input, prompt injection, bad parameters |
| Skill process -> cloud or SaaS API | read-only API calls or approved write calls | least privilege, secret handling, undeclared egress |
| Skill process -> sink or warehouse | persisted findings, evidence, or audit records | injection, schema drift, partial writes |
| MCP wrapper -> local skill | tool selection, context propagation, exit status | rogue tool behavior, hidden writes, audit gaps |
| CI or release pipeline -> published artifact | packaged code, SBOM, signatures | supply-chain tampering, unsigned release data |

## Threat Actors

| Actor | What they want | Most relevant controls |
|---|---|---|
| Malicious or careless caller | trick a skill into unsafe behavior or exfiltration | `SKILL.md` non-goals, fixed entrypoints, no generic shell passthrough, read-only defaults |
| Rogue or over-permissioned agent | invoke write paths without approval or widen scope silently | MCP approval checks, `--dry-run` defaults, dedicated write-capable skill contracts |
| Tampered upstream input producer | feed malformed or adversarial logs, findings, or audit rows | defensive parsing, schema validation, warnings on stderr, deterministic output contracts |
| Supply-chain attacker | compromise a dependency, workflow, or release artifact | dependency policy, `pip-audit`, Bandit, SBOM generation and signing, release attachment |
| Over-privileged runtime principal | use a skill execution role to do more than intended | least-privilege IAM/RBAC, split read and write paths, documented permissions |
| Malicious or misconfigured downstream sink | store data incorrectly, duplicate writes, or expose sensitive records | append-only design, dedupe keys, dry-run-first, sink contracts, operator-owned encryption and retention |

## Threat Scenarios

| Scenario | Primary asset at risk | Repo controls and evidence |
|---|---|---|
| Untrusted logs or findings attempt prompt injection or instruction smuggling into an agent flow | caller decision quality, downstream actions | Skills are standalone subprocesses, not prompt-bearing agents. The MCP wrapper exposes fixed tools, not arbitrary shell. Read-only skills do not recruit sibling skills. See [../SECURITY_BAR.md](../SECURITY_BAR.md) principle 11 and [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md). |
| A read-only skill performs hidden writes or undeclared side effects | cloud resources, sink state, customer trust | Read-only by default is a documented repo invariant. Skill contracts declare `side_effects`, `approval_model`, and `execution_modes`. CI validates safe-skill bar assumptions and source review checks no write SDK calls appear outside approved layers. |
| SQL or shell injection through source adapters, sinks, or runners | lake data, sink integrity, runtime host | Subprocess calls use list args with `shell=False`. Snowflake sink uses validated identifiers plus parameter binding. ClickHouse sink uses the client insert API. Source adapters restrict query shapes and statements. See [../SECURITY_BAR.md](../SECURITY_BAR.md) principle 9. |
| Secrets, tokens, or connection strings leak into stdout, stderr, findings, or audit rows | credentials, customer data | Secret-minimizing posture is documented in [../SECURITY.md](../SECURITY.md) and [CREDENTIAL_PROVENANCE.md](CREDENTIAL_PROVENANCE.md). CI checks for hardcoded secrets. Runtime guidance says not to echo secrets in telemetry, examples, or findings. |
| A remediation or sink path executes without real human approval | production state, identity posture, compliance evidence | Write-capable skills are isolated and dry-run-first. MCP rejects destructive flows without approval context and dry-run semantics. Remediation contracts carry explicit approver roles and blast-radius docs. Sink contracts document human approval and append-only expectations. |
| Replay or duplicate delivery causes duplicate findings or repeated writes | sink accuracy, remediation correctness, downstream cost | Deterministic UIDs, dedupe stores, append-only audit patterns, and replay-safe runner designs are part of the runtime contract. The shipped runners use per-finding dedupe behavior. Remediation keeps dual audit paths. |
| Schema drift or deprecated vendor APIs silently corrupt outputs | finding fidelity, downstream analytics, customer trust | The repo uses frozen golden fixtures, contract validation, framework coverage checks, and explicit schema docs. `native`, `ocsf`, `canonical`, and `bridge` are documented rather than inferred. See [SCHEMA_VERSIONING.md](SCHEMA_VERSIONING.md) and [SCHEMA_COVERAGE.md](SCHEMA_COVERAGE.md). |
| Dependency or release tampering causes consumers to run untrusted code | release integrity, procurement trust | CI runs `pip-audit`, Bandit, and validation lanes. A signed CycloneDX SBOM is generated and attached to releases. Dependency trust policy is documented in [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md). |

## Mitigation Themes

### Read-only first

Most skills are intentionally narrow, deterministic, and read-only. This limits
blast radius even when an operator runs them against production data.

Key evidence:

- [../SECURITY_BAR.md](../SECURITY_BAR.md)
- [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md)
- per-skill frontmatter in `SKILL.md`

### Write paths isolated and gated

The repo treats remediation, sinks, and runner edges as separate trust zones.
Those paths must be:

- explicit
- dry-run-first where applicable
- documented for blast radius
- backed by dedicated credentials
- auditable

Key evidence:

- [SINK_CONTRACT.md](SINK_CONTRACT.md)
- [RUNNER_CONTRACT.md](RUNNER_CONTRACT.md)
- `iam-departures-aws`

### Defensive parsing and deterministic outputs

Skills are expected to parse defensively, skip malformed records safely, and
emit stable identifiers and schemas.

Key evidence:

- golden fixtures under `skills/detection-engineering/golden/`
- contract and integrity validators under `scripts/`
- [SCHEMA_VERSIONING.md](SCHEMA_VERSIONING.md)
- [NATIVE_VS_OCSF.md](NATIVE_VS_OCSF.md)

### Supply-chain transparency

The repo treats dependency additions, SBOM generation, and release signatures as
security-relevant behavior, not release garnish.

Key evidence:

- [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)
- `.github/workflows/ci.yml`
- `.github/workflows/release-assets.yml`

## Residual Risks And Operator Responsibilities

This repo narrows risk; it does not remove the operator's responsibilities.

Operators still need to decide and enforce:

- runtime placement and network segmentation
- key management and encryption at rest
- sink retention and access control
- IAM scoping in their own accounts and projects
- review and approval workflow for destructive actions
- whether raw high-risk payloads should be retained or minimized

The repo also does not claim:

- immunity to malformed or adversarial upstream data
- perfect semantic coverage for every OCSF domain
- automatic safe execution in an over-privileged runtime

Those risks are documented so adopters can make explicit decisions rather than
assuming a hidden control plane exists.

## Review Checklist

When reviewing a new skill, sink, runner, or source adapter, ask:

1. Is the trust boundary explicit?
2. Are credentials and network egress scoped to the minimum necessary?
3. If it writes, is the path dry-run-first or otherwise approval-gated?
4. Is the input parsed defensively and the output schema documented?
5. Is the behavior deterministic enough for replay, dedupe, and audit?
6. Is the control backed by a validator, test, or contract doc rather than prose alone?

If the answer to any of those is "no," the change is not yet at the repo's
security bar.
