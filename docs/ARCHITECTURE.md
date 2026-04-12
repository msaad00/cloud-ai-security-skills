# Architecture

This document is the load-bearing design contract for `cloud-security`. Every future PR is reviewed against it. If you need to deviate, update this doc *in the same PR* — the contract drifts by design, never by accident.

- **Wire format contract** — see [`../skills/detection-engineering/OCSF_CONTRACT.md`](../skills/detection-engineering/OCSF_CONTRACT.md)
- **Sink / persistence contract** — see [`./SINK_CONTRACT.md`](./SINK_CONTRACT.md) *(lands with PR T)*
- **Runner / streaming contract** — see [`./RUNNER_CONTRACT.md`](./RUNNER_CONTRACT.md) *(lands with PR V)*
- **Visual guide** — see [`./DIAGRAMS.md`](./DIAGRAMS.md) for the architecture and data-flow diagrams in both markdown-native and SVG-friendly form

## 1. Purpose and scope

`cloud-security` is a library of **composable, OCSF-native security skills** that normalize, enrich, detect on, evaluate, remediate, and deliver findings across cloud providers and SaaS products. The repository is designed to be driven by agentic tools (Claude Code, Snowflake Cortex Code CLI, Claude Agent SDK, any MCP client) *and* by traditional CI / serverless pipelines — with no code changes between the two modes.

**In scope**
- Normalising raw vendor telemetry into OCSF 1.8 wire format
- Running deterministic detection rules on OCSF streams
- Evaluating OCSF streams against compliance benchmarks (CIS, NIST, PCI)
- Producing remediation proposals (and, when explicitly authorised, executing them)
- Converting OCSF into downstream wire formats (SARIF, Sigma, Jira, Mermaid)
- Persisting OCSF into columnar / lakehouse stores (Snowflake, AWS Security Lake, ClickHouse, BigQuery)
- Exposing every skill as an MCP tool so the same logic runs in every agent

**Out of scope (explicit non-goals)**
- Being a SIEM. SIEMs already ingest OCSF natively (Splunk, Sentinel, Chronicle, Elastic); we are the *producer* of OCSF, not a replacement for the consumer.
- Running a long-lived multi-tenant SaaS runtime. We ship a skills library + reference runners + reference sinks. Productionising those is the operator's responsibility.
- Inventing new telemetry schemas. OCSF 1.8 is the ceiling. If OCSF doesn't have a field, we use its `unmapped` escape hatch or a documented custom profile (see `OCSF_CONTRACT.md`).
- Real-time sub-second detection. Latency target is minute-scale batches. If you need sub-second, use a streaming runtime (Flink, Kafka Streams) with these skills as UDFs.

## 2. Design principles

These are the non-negotiables. Everything in §3–§8 exists to serve them.

1. **Skills are pure functions.** Input JSONL → output JSONL. No side effects. No cloud API calls. No disk writes outside stdout. No hidden state.
2. **Side effects live at the edges.** Exactly four categories may have side effects: **L0 sources** (read raw), **L5 remediate** (write cloud APIs), **L7 sinks** (write storage), **runners** (drive loops). Everything else is pure.
3. **The wire contract is the only shared dependency.** Skills never import from each other. If two skills need the same logic, they each own a copy. Copy-paste beats coupling at this scale — the wire format is the API, not the Python.
4. **Determinism.** Same input always produces the same output. Every finding UID is a content hash; no random UUIDs. Replayable ⇒ testable ⇒ idempotent sink merges.
5. **Read-only by default.** A skill may only perform writes if it is prefixed `remediate-*` or `sink-*` and its `SKILL.md` carries an explicit "Do NOT use" clause describing the blast radius.
6. **Least-privilege infra.** Every skill that talks to a cloud API ships the *minimum* IAM policy in `infra/iam_policies/`. Wildcard actions are a CI failure.
7. **MCP-exposable by default.** Every skill must be wrappable as an MCP tool with zero code changes: stdin+args in, stdout out, non-zero exit on error, stderr for warnings. Skills that can't satisfy this don't ship.
8. **Idempotent sinks.** Every sink does `MERGE ... ON finding_info.uid`. Re-runs converge. No blind-insert mode.
9. **Dry-run everywhere writes happen.** `--dry-run` is mandatory for every `remediate-*` and `sink-*` skill. It prints the SQL / API calls it *would* make without making them.
10. **Audit the auditor.** Every sink write and every remediation action emits *itself* as an OCSF Application Activity (6002) event, so the tool's own actions are findable in the same pipeline it feeds.

## 3. The 9 layers

```
 ┌───────────────────────────────────────────────────────────────────┐
 │ L0  SOURCES         raw vendor formats (CloudTrail, VPC Flow,     │
 │                     Okta, Ramp, Snowflake audit, K8s audit, ...)  │
 ├───────────────────────────────────────────────────────────────────┤
 │ L1  INGEST          raw → OCSF 1.8 wire format                    │
 │                     ingest-cloudtrail-ocsf, ingest-ramp-ocsf, ... │
 ├───────────────────────────────────────────────────────────────────┤
 │ L2  ENRICH          OCSF → OCSF + context                         │
 │                     enrich-asset-inventory, enrich-geoip,         │
 │                     enrich-mitre-navigator, enrich-pii-redact     │
 ├───────────────────────────────────────────────────────────────────┤
 │ L3  DETECT          OCSF → OCSF Detection Finding (2004)          │
 │                     detect-lateral-movement-aws, detect-*         │
 ├───────────────────────────────────────────────────────────────────┤
 │ L4  EVALUATE        OCSF → compliance pass/fail + evidence        │
 │                     cspm-*-cis-benchmark, evaluate-nist-ai-rmf    │
 ├───────────────────────────────────────────────────────────────────┤
 │ L5  REMEDIATE       Finding → IaC patch / SOAR action             │
 │                     iam-departures-remediation, revoke-key-*      │
 ├───────────────────────────────────────────────────────────────────┤
 │ L6  CONVERT         OCSF → other wire formats for delivery        │
 │                     convert-ocsf-to-sarif, to-sigma, to-jira,     │
 │                     to-mermaid-attack-flow                        │
 ├───────────────────────────────────────────────────────────────────┤
 │ L7  SINKS (opt)     OCSF → persisted store                        │
 │                     sink-snowflake, sink-security-lake,           │
 │                     sink-clickhouse, sink-bigquery                │
 ├───────────────────────────────────────────────────────────────────┤
 │ L8  QUERY / VIZ     SQL packs + Grafana packs + Cortex prompts    │
 │                     query-mitre-heatmap, cortex-triage-prompts    │
 ├───────────────────────────────────────────────────────────────────┤
 │ L9  AGENT SURFACE   mcp-server exposes every skill as a tool      │
 │                     → Claude Code, Cortex Code, Agent SDK         │
 └───────────────────────────────────────────────────────────────────┘
```

Every data object flowing between layers is **OCSF 1.8 JSONL**. No layer invents a new wire format. Converters (L6) emit *other* formats only for downstream delivery — never as intermediate state.

### Visuals

For quick orientation, use the visual set in [`DIAGRAMS.md`](./DIAGRAMS.md):

- **Repo architecture** — [`repo-architecture.svg`](./images/repo-architecture.svg)
- **IAM departures data flow** — [`iam-departures-data-flow.svg`](./images/iam-departures-data-flow.svg)
- **Detection pipeline** — [`detection-pipeline.svg`](./images/detection-pipeline.svg)

The rule for this repo is simple: keep the architecture readable in Markdown, and keep polished SVGs in `docs/images/` for rendered docs.

### Layer status snapshot

| Layer | Category | Status | Skills shipped | Roadmap |
|---|---|---|---|---|
| L0 | sources | (external) | n/a | vendor stories #30–#36, Ramp (PR Y), Snowflake audit (PR Z) |
| L1 | `ingest-*` | **shipping** | cloudtrail, vpc-flow-logs, guardduty, security-hub, gcp-audit, azure-activity, k8s-audit, mcp-proxy | gcp-vpc-flow, azure-nsg-flow, okta, github, workspace, slack, ramp |
| L2 | `enrich-*` | **planned** | none | PR X (asset-inventory, geoip, mitre-navigator, **pii-redact is P0 before any sink in regulated env**) |
| L3 | `detect-*` | **shipping** | lateral-movement-aws, privesc-k8s, sensitive-secret-read-k8s, mcp-tool-drift | credential-access per cloud, unusual-assume-role, vector-store-poisoning |
| L4 | `evaluate-*` | **shipping** | cspm-aws/gcp/azure-cis-benchmark, k8s-security-benchmark, container-security | evaluate-cis-aws-foundations (#29), NIST AI RMF, SOC2, PCI |
| L5 | `remediate-*` | **shipping** | iam-departures-remediation | auto-close-exposed-s3, revoke-long-lived-key, patch-inspector-finding |
| L6 | `convert-*` | **shipping** | ocsf-to-sarif, ocsf-to-mermaid-attack-flow | to-sigma, to-splunk-cim, to-jira, to-opa-rego |
| L7 | `sinks/` | **planned** | none | PR T (snowflake), PR W (security-lake), PR AA (clickhouse), bigquery |
| L8 | `query/` + packs | **planned** | none | PR T ships the first Cortex query pack alongside sink-snowflake |
| L9 | `mcp-server/` | **planned** | none | PR U — the unlock for Cortex Code CLI integration |

## 4. Two execution modes

Skills never change between modes. What changes is **what drives them**.

### Mode A — Batch (stateless)

Finite input, pipe through skills, write the output somewhere. This is the default mode and the only one required for a working install.

```
cat cloudtrail.json \
  | python3 skills/detection-engineering/ingest-cloudtrail-ocsf/src/ingest.py \
  | python3 skills/detection-engineering/detect-lateral-movement-aws/src/detect.py \
  | python3 skills/detection-engineering/convert-ocsf-to-sarif/src/convert.py \
  > findings.sarif
```

Used by: Claude Code ad-hoc analysis, CI, one-off investigations, compliance snapshots, `gh pr review` automation.

Properties: zero infrastructure, no state, perfectly reproducible, no persistence, single-shot.

### Mode B — Streaming / continuous

A **runner** (L9 driver, not a skill) drives the skills in a loop from a source queue to a sink. The runner is the only component with state (checkpoint offsets).

```
 S3 notification SQS           skill loop                    sink
 ─────────────────▶  runner-s3-to-snowflake  ─▶  ingest-* → detect-* → sink-snowflake
                         │
                         └─ checkpoint state in DynamoDB / Snowflake STREAM
```

Example runners (none exist yet — land in PR V):
```
runners/runner-s3-to-snowflake          # S3 → skill → Snowflake COPY INTO
runners/runner-eventbridge-to-security-lake   # EventBridge → skill → Parquet → Security Lake
runners/runner-pubsub-to-clickhouse     # Google Pub/Sub → skill → ClickHouse INSERT
runners/runner-eventhubs-to-bigquery    # Azure Event Hubs → skill → BigQuery JSON load
```

Properties: persistent state lives *only* in the runner (checkpoint) and sink (materialised rows). The skills themselves remain stateless, so failure recovery is: re-drive the runner from the last checkpoint, let idempotent sink merges collapse the duplicates.

### Why this works: idempotency

Every OCSF event we emit carries a deterministic UID derived from content, never from wall clock or RNG. Today:

- **Findings**: `finding_info.uid = det-<rule>-<short(semantic_key)>`. Example: `det-aws-lm-cbef99b7-9ea97278` is the (session, dst-ip, dst-port) hash for the AWS lateral-movement rule. Running the same input a thousand times yields the same uid.
- **Ingested events**: inherit the source event's immutable ID (`eventID` for CloudTrail, `Id` for GuardDuty, etc.). Ingest is content-addressable.

Sinks exploit this: `MERGE INTO ocsf_findings USING input ON input.finding_info.uid = target.finding_info.uid WHEN MATCHED THEN UPDATE SET ... WHEN NOT MATCHED THEN INSERT ...`. Replaying a day's worth of raw events after a sink outage **converges to the same table state**.

## 5. Directory layout

### Current (pre-reshape)

```
cloud-security/
├── skills/
│   ├── ai-infra-security/       # discover, gpu-cluster, model-serving
│   ├── compliance-cis-mitre/    # → will become `evaluate/`
│   ├── detection-engineering/   # ingest-*, enrich-*, detect-*, convert-*
│   └── remediation/             # → will become `remediate/`
├── tests/integration/
├── .github/workflows/
└── docs/
    └── ARCHITECTURE.md  (this file)
```

### Target (post-reshape PR #39)

```
cloud-security/
├── skills/
│   ├── ingest-*              # L1
│   ├── enrich-*              # L2
│   ├── detect-*              # L3
│   ├── evaluate-*            # L4 (was compliance-cis-mitre/)
│   ├── remediate-*           # L5 (was remediation/)
│   └── convert-*             # L6
├── sinks/                    # L7 — own top-level, side-effectful
│   ├── sink-snowflake-ocsf/
│   ├── sink-security-lake-ocsf/
│   └── sink-clickhouse-ocsf/
├── runners/                  # Mode B drivers
│   ├── runner-s3-to-snowflake/
│   └── runner-eventbridge-to-security-lake/
├── mcp-server/               # L9 — single cross-cutting server
│   ├── src/server.py
│   ├── src/tool_registry.py
│   └── tests/
├── query/                    # L8 — SQL packs, Cortex prompts, Grafana JSON
│   ├── snowflake/
│   ├── clickhouse/
│   └── grafana/
├── tests/integration/
└── docs/
    ├── ARCHITECTURE.md
    ├── OCSF_CONTRACT.md       # moved from skills/detection-engineering/
    ├── SINK_CONTRACT.md       # new, PR T
    └── RUNNER_CONTRACT.md     # new, PR V
```

**Rationale for separating `sinks/`, `runners/`, `mcp-server/`, `query/` from `skills/`:** the "skills are pure, edges have side effects" mental model becomes visible in the directory tree. A reviewer can tell at a glance whether a change touches pure code or effectful code. This is cheap documentation that pays for itself on every PR.

**Migration mechanics** — the reshape is tracked as issue #39 and is a mechanical `git mv` + import-path update. The directory names are stable public API for skill consumers; we will ship a one-release deprecation window where the old paths re-export from the new paths.

## 6. Wire contract (OCSF 1.8)

See [`../skills/detection-engineering/OCSF_CONTRACT.md`](../skills/detection-engineering/OCSF_CONTRACT.md) for the field-level contract every event must satisfy. Summary:

- **Base schema:** OCSF 1.8.0, no exceptions.
- **Wire format:** JSONL, UTF-8, LF, no BOM.
- **Transport:** stdin / stdout by default, `--input` / `--output` optional.
- **Error handling:** malformed lines are skipped with a stderr warning — never fatal. Detection pipelines must not crash on one bad event.
- **Detection findings:** class **2004** (`Detection Finding`). Class 2001 (`Security Finding`) is deprecated since OCSF 1.1 and forbidden in this repo.
- **MITRE ATT&CK:** version v14, pinned. `attacks[]` lives inside `finding_info`, not at the event root.
- **Custom fields:** forbidden at the base level. Custom MCP-specific fields live under a documented profile extension (`cloud_security_mcp`).

### Event UID rules

| Event kind | UID derivation |
|---|---|
| Ingested (L1) | Inherit source event's immutable ID (CloudTrail `eventID`, GuardDuty `Id`, ASFF `Id`, K8s audit `auditID`). |
| Detection finding (L3) | `det-<rule-slug>-<short-sha256(semantic-key)>` where semantic-key is the tuple of observables that defines "the same finding" (session + dst for lateral movement, cluster + subject for k8s privesc, etc.). |
| Compliance finding (L4) | `eval-<benchmark>-<control-id>-<target-uid>`. Same target evaluated twice must yield the same UID. |
| Remediation action (L5) | `remediate-<action>-<target-uid>-<ts-day>`. Day-bucketed so the same day's replay dedupes but tomorrow's re-run creates a new audit record. |
| Sink audit (L7) | `sink-<sink-name>-<input-uid>`. Emitted as an OCSF 6002 self-audit event per rule 10. |

## 7. Guardrails (10 rules, expanded)

Each rule, the reason, and the concrete enforcement mechanism.

1. **Pure functions.** *Enforcement:* CI runs `bandit` with `B310` (urllib) and `B605` (subprocess) enabled on everything under `skills/` except `remediate-*`, `sink-*`, and `runners/`. Any network or subprocess call outside those categories fails the build.

2. **Side effects live at the edges.** *Enforcement:* `CODEOWNERS` requires a security reviewer on any PR that touches `remediate-*/`, `sink-*/`, or `runners/`. Pure-skill PRs don't need this.

3. **No cross-skill imports.** *Enforcement:* CI lint rule — any `from ..` or `from ...` import inside `skills/*/*/src/` fails. A skill may import only from its own `src/` or from the Python stdlib.

4. **Determinism.** *Enforcement:* every skill ships golden fixtures and a `test_deep_eq_against_frozen_golden` test. Re-running the skill against the raw input must produce byte-identical output to the frozen OCSF JSONL.

5. **Read-only by default.** *Enforcement:* `SKILL.md` frontmatter has a required `capability` field. Valid values: `read-only`, `write-remediation`, `write-sink`, `write-runner`. CI rejects a skill with no `capability` field.

6. **Least-privilege IAM.** *Enforcement:* every `remediate-*` and `sink-*` skill ships `infra/iam_policies/*.json`. CI runs `iam-policy-lint` to reject wildcard `Action: "*"` or wildcard `Resource: "*"` unless the policy carries an explicit `# WILDCARD_OK: reason` comment.

7. **MCP-exposable.** *Enforcement:* the `mcp-server/` test suite auto-discovers every skill and calls it via the MCP protocol with its golden input. Any skill that doesn't round-trip through MCP fails the build.

8. **Idempotent sinks.** *Enforcement:* `SINK_CONTRACT.md` defines the required MERGE key (`finding_info.uid` for finding classes, source event ID for ingested classes). A sink's test suite must run the golden fixture twice and assert the target row count is unchanged on the second run.

9. **Dry-run everywhere writes happen.** *Enforcement:* every `remediate-*` and `sink-*` skill must accept `--dry-run` and its test suite must verify zero writes occur when the flag is set.

10. **Audit the auditor.** *Enforcement:* every sink write emits an OCSF 6002 Application Activity event to a separate `sink_audit` stream. Grafana / Cortex has a dashboard pack that surfaces "who wrote what when".

## 8. Agent integration — the MCP layer

This section is the heart of the design. Without it, each agent (Claude Code, Cortex Code, Agent SDK, custom) would need per-agent glue. With it, **writing a new skill automatically makes it available to every agent.**

### Architecture

```
┌──────────────────┐
│  Claude Code     │── Bash tool (direct) ──────┐
├──────────────────┤                            │
│  Claude Code     │── MCP client ───┐          │
├──────────────────┤                 │          │
│  Cortex Code CLI │── MCP client ───┤          │
├──────────────────┤                 │          │
│  Claude Agent SDK│── MCP client ───┼──────►  mcp-server ◄── auto-discovers
├──────────────────┤                 │            │           skills/*/src/*.py
│  custom agent    │── MCP stdio ────┘            │
└──────────────────┘                              ▼
                                          subprocess invoke
                                           (stdin JSONL in,
                                            stdout JSONL out)
```

### How `mcp-server/` works (PR U)

1. **Auto-discovery** — walks `skills/*/*/SKILL.md`, parses the frontmatter (`name`, `description`, `capability`), and derives the entrypoint (`src/<ingest|detect|checks|convert|...>.py`).
2. **Tool spec generation** — each skill becomes one MCP tool. Tool name = `SKILL.md` `name` field. Tool description = the full frontmatter `description` (which already leads with "Use when…" and closes with "Do NOT use…" per the Anthropic pattern).
3. **Input schema** — derived from the skill's `argparse` spec. Required JSONL input is modeled as a tool parameter `input: string` (inline JSONL) or `input_uri: string` (S3/GS/blob URL the server will fetch).
4. **Invocation** — the server shells out to `python3 <skill-path>/src/<entry>.py`, streams the tool's `input` to the skill's stdin, captures stdout, wraps non-zero exits as MCP errors with stderr attached.
5. **Transport** — stdio (local) and HTTP/SSE (remote). stdio is enough for Claude Code and Cortex Code CLI; HTTP/SSE is for hosted multi-agent deployments.

### Why MCP and not a bespoke API

- Claude Code can call skills via Bash *or* MCP — flexibility is free.
- Cortex Code CLI supports *only* MCP (no general Bash tool), so MCP is the **required** path for Snowflake-agent coverage.
- Claude Agent SDK has first-class MCP support.
- Any custom agent with an MCP client (growing list) gets the library for free.
- MCP is an open protocol; we incur no vendor lock-in by adopting it.

### What MCP does **not** do

- It does not make skills stateful. The server is a thin wrapper; state still lives only in sinks and runners.
- It does not aggregate results. A multi-step analysis is still a composition of tool calls orchestrated by the agent, not a monolithic "analyze_everything" endpoint.
- It does not authenticate end users. Auth is the embedding application's responsibility — the MCP server trusts its caller.

## 9. Security posture

This section governs what happens the moment the repo graduates from "Unix filter toy" to "persistent security telemetry pipeline" (i.e. any time a sink or runner is deployed).

| Concern | Control | Enforced where |
|---|---|---|
| Encryption at rest | Native: Snowflake column encryption, Security Lake S3 SSE-KMS, ClickHouse disk encryption | Sink DDL ships with encryption enabled; CI rejects unencrypted table definitions |
| Encryption in transit | TLS 1.2+ on every connection; sinks reject plaintext | Sink connection code validates scheme |
| Credentials | Vault / Secrets Manager / KMS-wrapped only. Sinks refuse to run if a literal long-lived key is in env. | Sink startup check |
| IAM | Per-sink role: `CREATE TABLE` + `MERGE INTO` on `ocsf_*` schema, nothing else. Policy shipped in `infra/iam_policies/<sink-name>.json`. | `iam-policy-lint` CI check |
| Multi-tenancy | Row-level security on `cloud.account.uid`. Snowflake RLS policy, ClickHouse row policy, Security Lake S3 prefix partitioning. | Sink schema ships the RLS / row-policy DDL |
| Retention | Storage-layer TTL. Default 90d hot, auto-archive to 7y for audit classes. | DDL |
| PII | Field-level redaction hook at L2 (`enrich-pii-redact-ocsf`, PR X-P0) **must** run before any sink in a regulated environment. Config file defines redaction rules per field path. | Runner refuses to start a pipeline targeting a sink without PII redaction enabled, unless `--regulated=false` is set explicitly |
| Tamper detection | Sinks sign each batch with a rolling HMAC over a key in KMS. Downstream `query-tamper-check` skill detects gaps and signature mismatches. | SINK_CONTRACT.md, PR T |
| Separation of duties | `sink-*` skills run with **write-only** creds (no SELECT grant). `query-*` skills run with **read-only** creds. They never share a role. | IAM policies |
| Audit | Every sink write and every remediation action emits an OCSF 6002 self-audit event into a separate `sink_audit` stream. | Rule 10 |
| Network | Sinks must tolerate egress restrictions — all use official vendor SDKs which honour VPC endpoints / private links. | Test suite runs sinks with `http_proxy=invalid` and asserts they use the SDK, not direct HTTP |

## 10. Determinism and idempotency — worked example

This is the property that lets Mode A and Mode B share the same skill code. Worked example using `detect-lateral-movement-aws`:

**Input** — one CloudTrail AssumeRole event + one VPC Flow ACCEPT to 10.0.3.75:3306, same session.

**Deterministic UID** — rule computes `session_uid = "ASIASESSION001"`, `dst_key = "10.0.3.75:3306"`, then `uid = "det-aws-lm-" + sha256(session_uid)[:8] + "-" + sha256(dst_key)[:8]`. This yields `det-aws-lm-cbef99b7-9ea97278` regardless of when or where the rule runs.

**Replay scenarios:**

| Scenario | Sink behaviour |
|---|---|
| Raw events fed once, sink healthy | 1 row inserted |
| Raw events fed again (Mode B retry after outage) | `MERGE` matches on uid → `UPDATE` (no-op if payload unchanged) |
| Raw events fed with a new flow at 5 min 10s (second flow, same session, same dst) | Deduped in-skill by `(session, dst_ip, dst_port)` — still 1 uid, still 1 row |
| Raw events fed with a flow to a *different* dst | New uid, new row |
| Day's worth of raw events replayed from S3 after a 6h sink outage | Every finding's `MERGE` key already exists → 0 duplicates, converged state |

This is what "OCSF can persist + update" means in practice: every finding is *already* an upsert key. The sink never needs a generated primary key.

## 11. Extending the repo

### Adding a new skill

1. Pick the layer (L1 ingest, L2 enrich, L3 detect, L4 evaluate, L5 remediate, L6 convert).
2. Copy the nearest sibling as the starting point — the existing skills in the target category are the canonical reference.
3. Write `SKILL.md` with the spec-compliant frontmatter, leading `description` with "Use when…" and closing with "Do NOT use…". Include the `capability` field.
4. Implement `src/<entry>.py` as a pure Unix filter: stdin JSONL in, stdout JSONL out, stderr for warnings.
5. Write tests in `tests/test_<entry>.py`. Include:
   - Unit tests for every helper.
   - Positive golden-fixture parity tests.
   - Negative controls (at least 3, explaining what should **not** fire).
6. Register the skill in `.github/workflows/ci.yml` matrix.
7. If the skill adds a new MITRE technique, add it to `OCSF_CONTRACT.md`'s pinned table.
8. Run `pytest`, `ruff check`, `ruff format`, open a PR.

### Adding a new sink (PR T pattern)

1. Create `sinks/sink-<name>-ocsf/` with the same SKILL.md + src + tests + infra layout.
2. Ship `infra/schema.sql` with encrypted, RLS-policied DDL.
3. Ship `infra/iam_policies/sink-write.json` with minimum grants.
4. Implement a pure mode A pathway: `cat ocsf.jsonl | python src/load.py --dry-run` prints the exact SQL / API calls.
5. Implement the wet pathway behind `--dry-run=false`.
6. Add two idempotency tests: same input run twice must yield unchanged row count.
7. Add a sink-audit test: confirm the sink emits an OCSF 6002 event about itself.
8. Add CI matrix entry.

### Adding a new runner (PR V pattern)

1. Create `runners/runner-<source>-to-<sink>/` with SKILL.md + src + tests.
2. Implement checkpoint persistence (DynamoDB, Snowflake STREAM, GCS blob, Azure Storage — pick one per runner).
3. Runner must be idempotent against checkpoint replay: running from `checkpoint_n - 10 batches` must converge.
4. Test with a fake source queue and a fake sink that records its MERGE operations.

## 12. Versioning and compatibility

- The **wire contract** (OCSF version + custom profile version + MITRE version) is pinned in `OCSF_CONTRACT.md` under `contract version: 1.8.0+mcp.2026.04`. To bump: cut a new contract version and re-freeze every skill's golden fixtures in one PR. We do not mix contract versions across skills.
- **Skill implementations** are versioned by git commit. A skill has no version number; its behaviour is defined by its test fixtures, which are frozen.
- **Repo releases** cut tagged versions (`v0.N.M`) that snapshot a known-good combination of contract + skills + sinks + runners. CI smoke-tests the release's end-to-end pipes before the tag is pushed.
- **Breaking changes** to the contract are allowed at minor-version boundaries, must update every skill in the same PR, and must ship a migration note in `docs/MIGRATIONS.md`.

## 13. Roadmap (dependency-ordered)

This is the architectural roadmap. Vendor-story PRs (#29–#39) continue in parallel and land on whatever the top-of-stack layout is.

| PR | Scope | Priority | Why |
|---|---|---|---|
| **ARCHITECTURE.md** | This document | **P0** | Locks the design so every subsequent PR lands correctly |
| **PR #39 reshape** | `git mv` skills into `ingest-*`, `evaluate-*`, `remediate-*`, etc. Add empty `sinks/` `runners/` `mcp-server/` `query/` dirs with READMEs. | **P0** | Without this, later PRs land in the wrong place and we pay for it twice |
| **PR U — mcp-server** | Auto-discover every skill, expose via MCP stdio + HTTP/SSE, test against Claude Code + Cortex Code CLI | **P0** | The single highest-leverage PR: unlocks every agent for every future skill |
| **PR T — sink-snowflake-ocsf** | Schema DDL, COPY INTO loader, idempotent MERGE, Cortex query pack, Cortex Analyst semantic model | **P0** | Proves the persistent mode works end-to-end, directly enables Cortex Code CLI users |
| **PR X — enrich-pii-redact-ocsf** | Field-level redaction with rule config, **gates every sink run in regulated mode** | **P0** | Regulatory prerequisite — no sink runs in a regulated environment without it |
| **PR V — first runner** | `runner-s3-to-snowflake` with checkpoint state, idempotency tests | P1 | Proves streaming mode works. Unlocks continuous pipeline |
| **PR W — sink-security-lake-ocsf** | OCSF Parquet with AWS Security Lake partitioning (zero-transform target) | P1 | Most strategic sink — AWS Security Lake *is* OCSF-native |
| **PR Y — Ramp vendor story** | `ingest-ramp-ocsf` + `detect-ramp-vendor-change-with-payment` + `detect-ramp-spend-limit-bypass` + `detect-ramp-card-to-unknown-merchant` | P1 | First non-cloud, business-logic vendor story |
| **PR Z — ingest-snowflake-audit-ocsf** | Snowflake `ACCOUNT_USAGE` audit into OCSF | P2 | Closes the loop: Cortex Code users can detect on their own platform |
| **PR AA — sink-clickhouse-ocsf** | MergeTree DDL, `Nested(…)` for `attacks[]` and `observables[]`, loader, Grafana dashboard pack | P2 | Best OLAP economics for high-cardinality teams |
| **PR BB — enrich-asset-inventory-ocsf** | Joins findings with `discover-environment` graph | P2 | Turns findings into triageable blast-radius context |

## 14. Non-goals (explicit)

To keep this doc honest:

- **Not a SIEM.** Splunk, Sentinel, Chronicle, and Elastic already consume OCSF natively. If you have one of those, pipe our output into it — we are the *producer*.
- **Not a runtime.** We ship a library + reference runners + reference sinks. Running a 24/7 multi-tenant production pipeline is an integration task the operator owns.
- **Not a rule engine.** We ship deterministic Python rules. If you need a declarative DSL, convert our OCSF to Sigma and load it into your DSL engine.
- **Not a UI.** `query/` ships SQL packs and Grafana dashboards; we do not ship a proprietary web UI. Grafana + Cortex are the "UI".
- **Not a SOAR.** `remediate-*` skills propose fixes. Production SOAR orchestration is the operator's responsibility.
- **Not a replacement for official SDKs.** Sinks use the official vendor SDK (Snowflake Python connector, `boto3`, `google-cloud-*`, `azure-*`). We do not reimplement API clients.

## 15. Glossary

| Term | Meaning |
|---|---|
| **Skill** | A self-contained Anthropic-spec skill bundle: `SKILL.md` + `src/` + `tests/` + optional `REFERENCES.md` + optional `infra/`. One purpose, one wire contract. |
| **Layer** | A logical stage in the pipeline (L0–L9). Each layer has exactly one category of side-effect profile. |
| **Sink** | A side-effectful skill that persists OCSF to external storage. Lives in `sinks/`, not `skills/`. |
| **Runner** | A driver process that runs skills in a loop from a source queue to a sink. Lives in `runners/`, not `skills/`. |
| **Wire contract** | The OCSF 1.8 + MITRE v14 + MCP-profile pinning in `OCSF_CONTRACT.md`. The only shared dependency. |
| **MCP tool** | An MCP-protocol-exposed callable. Every skill is automatically one, via `mcp-server/`. |
| **Mode A** | Batch execution. Finite input, Unix pipes, no persistence. The default. |
| **Mode B** | Streaming execution. Runner drives skills in a loop, state lives only in the runner checkpoint and the sink. |
| **Deterministic UID** | A content-addressed identifier. Same semantic input → same UID. The property that makes idempotent sinks work. |
| **Read-only by default** | The baseline posture: no skill performs writes unless it is `remediate-*` or `sink-*` and has an explicit "Do NOT use" clause. |

---

*Changelog — update this section in every PR that amends this file.*

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-04-11 | Initial architecture document. Codifies the 9-layer model, two execution modes, 10 guardrails, MCP integration strategy, security posture, and the dependency-ordered roadmap. |
