<div align="center">

# cloud-ai-security-skills

**Production-grade security skills for cloud and AI systems.**
Source-specific ingest, discovery, detection, evaluation, view, and remediation — one bundle, any surface.

[![CI](https://github.com/msaad00/cloud-ai-security-skills/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/msaad00/cloud-ai-security-skills/actions/workflows/ci.yml?query=branch%3Amain)
[![Version](https://img.shields.io/badge/version-0.5.0-0ea5e9)](CHANGELOG.md)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![OCSF 1.8](https://img.shields.io/badge/OCSF-1.8-22d3ee)](https://schema.ocsf.io/1.8.0)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-ef4444)](https://attack.mitre.org/)
[![CIS](https://img.shields.io/badge/CIS-AWS_%7C_GCP_%7C_Azure-22c55e)](docs/FRAMEWORK_MAPPINGS.md)
[![Coverage Gates](https://img.shields.io/badge/coverage-gated-0f766e)](docs/COVERAGE_MODEL.md)
[![Scanned by agent-bom](https://img.shields.io/badge/scanned_by-agent--bom-164e63)](https://github.com/msaad00/agent-bom)

<sub>AWS · GCP · Azure · Kubernetes · Okta · Microsoft Entra · Google Workspace · Snowflake · Databricks · ClickHouse · MCP</sub>

</div>

---

## What this repo gives you

**44 shipped skill bundles** that turn raw cloud, identity, Kubernetes, and MCP signals into stable, standards-aligned findings — and one guarded write path for offboarding. Each skill is a self-contained `SKILL.md + src/ + tests/` bundle that runs unchanged from the CLI, CI, MCP, or a persistent cloud runner.

| | Purpose | Output |
|---|---|---:|
| **15 × Ingest** | normalize raw source → event stream | native JSONL **or** OCSF 1.8 |
| **4 × Discover** | inventory, graph, AI BOM, evidence | native / bridge JSON |
| **9 × Detect** | deterministic rules with MITRE ATT&CK | OCSF Detection Finding 2004 |
| **7 × Evaluate** | 82 posture and benchmark checks | compliance result |
| **1 × Remediate** | IAM departures (HITL + dual audit) | audited action trail |
| **2 × View** | findings → review formats | SARIF · Mermaid |
| **6 × Edge** | warehouse source + sink adapters | native pass-through |

![Every shipped skill in the repo grouped by layer, with vendor logos and per-layer counts. Layer 1 Ingest has 15 normalizers across AWS, GCP, Azure, Kubernetes, Okta, Entra, Workspace, and MCP. Layer 2 Discover has 4 inventory and AI BOM skills. Layer 3 Detect has 9 MITRE-tagged rules. Layer 4 Evaluate has 7 benchmarks totaling 82 checks. Layer 5 Remediate ships IAM departures. Layer 6 View converts to SARIF and Mermaid. Edge adapters for Snowflake, Databricks, S3, and ClickHouse wrap the same contract.](docs/images/skill-map.svg)

## Mental model

Three action bands over six layers. The same bundle contract is shared across all of them.

![Repository architecture showing three action bands. Intake runs Ingest and Discover, Analyze runs Detect and Evaluate, Act runs View and guarded Remediate. External signals from cloud APIs, raw logs, identity feeds, Kubernetes audit, warehouses, and MCP proxy flow into the skill bundle contract underneath. Source and sink edges, SQL query packs, and runtime surfaces CLI, CI, MCP, and runners all wrap the same implementation.](docs/images/repo-architecture.svg)

- **L1 Ingest** · raw source → stable stream · [`ingest-*`](skills/ingestion/)
- **L2 Discover** · live inventory and evidence · [`discover-*`](skills/discovery/)
- **L3 Detect** · deterministic attack findings · [`detect-*`](skills/detection/)
- **L4 Evaluate** · benchmark and posture · [`evaluation/*`](skills/evaluation/)
- **L5 Remediate** · guarded writes · [`iam-departures-remediation`](skills/remediation/iam-departures-remediation/)
- **L6 View** · exports and renders · [`convert-ocsf-*`](skills/view/)

Full contract: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Agent and runtime integrations

MCP clients, CLI, CI, and cloud runners all reach the same skill bundle. Wrappers add transport, queues, and audit — never a second implementation.

![Agent and runtime integrations showing five MCP clients — Claude Code, OpenAI Codex, Cursor, Windsurf, and Cortex Code CLI — connecting over stdio to the repo-owned MCP server that auto-discovers SKILL.md files and exposes them as audited tool calls with correlation IDs and timeouts. CLI, CI, and persistent AWS, GCP, and Azure runners reach the same shared skill bundle directly. Outputs are native JSONL, OCSF 1.8 JSONL, bridge, SARIF, Mermaid attack flow, and audited writes.](docs/images/agent-integrations.svg)

- **MCP** · [.mcp.json](.mcp.json) · [mcp-server/README.md](mcp-server/README.md) · [docs/MCP_AUDIT_CONTRACT.md](docs/MCP_AUDIT_CONTRACT.md)
- **CLI / pipes** · stdin/stdout bundles compose into one-liners
- **CI** · GitHub Actions publishes SARIF to the Security tab
- **Runners** · reference runners under [runners/](runners/) for S3/SQS, GCS/PubSub, Blob/EventGrid

## Start here

Pick the row that matches the job.

| You have… | Start with | Typical output |
|---|---|---|
| a raw log file or stream | [`ingest-*`](skills/ingestion/) → [`detect-*`](skills/detection/) | OCSF Detection Finding |
| live cloud API access | [`discover-*`](skills/discovery/) or [`evaluation/*`](skills/evaluation/) | graph / benchmark JSON |
| warehouse rows (Snowflake, Databricks, S3) | [`source-*`](skills/ingestion/) → `detect-*` → [`sink-*`](skills/remediation/) | customer-owned persistence |
| an AI estate to inventory | [`discover-ai-bom`](skills/discovery/discover-ai-bom/) | CycloneDX-aligned AI BOM |
| audit evidence to produce | [`discover-control-evidence`](skills/discovery/discover-control-evidence/) | PCI / SOC 2 evidence JSON |
| OCSF findings to publish | [`view/*`](skills/view/) | SARIF · Mermaid |
| a departing employee to offboard | [`iam-departures-remediation`](skills/remediation/iam-departures-remediation/) | dry-run plan or audited action |

Full crosswalk: [docs/USE_CASES.md](docs/USE_CASES.md)

## Common shipped flows

Three concrete lanes. Same skill bundle contract in every lane — what changes is the input, output, and control boundary.

![Common shipped flows showing three shipped compositions. Raw payloads flow ingest to detect to view. Warehouse or object rows flow source to detect to sink. Live cloud, SaaS, or HR state flows through discovery or evaluation, optionally through guarded remediation. Access surfaces CLI, MCP, CI, and AWS or GCP or Azure runners all invoke the same bundle.](docs/images/end-to-end-skill-flows.svg)

**Example — Kubernetes privilege escalation, end-to-end:**

```bash
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py \
  skills/detection-engineering/golden/k8s_audit_raw_sample.jsonl \
  | python skills/detection/detect-privilege-escalation-k8s/src/detect.py \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py \
  > findings.sarif
```

**Same flow from an MCP agent:**

```text
tools/call name="ingest-k8s-audit-ocsf" args={"args":["skills/detection-engineering/golden/k8s_audit_raw_sample.jsonl"]}
tools/call name="detect-privilege-escalation-k8s" args={"input":"<stdout>"}
tools/call name="convert-ocsf-to-sarif"          args={"input":"<stdout>"}
```

The skill bundle is the product. CLI, CI, MCP, and runners are access paths.

<details>
<summary><b>What you get back</b></summary>

Raw audit line (abbreviated):
```json
{"kind":"Event","stage":"ResponseComplete","verb":"list","auditID":"k1-list-secrets","user":{"username":"system:serviceaccount:default:builder"}}
```

OCSF event (abbreviated):
```json
{"class_uid":6003,"class_name":"API Activity","metadata":{"uid":"k1-list-secrets"},"api":{"operation":"list"},"resources":[{"type":"secrets","namespace":"default"}]}
```

OCSF Detection Finding 2004 (abbreviated):
```json
{"class_uid":2004,"class_name":"Detection Finding","finding_info":{"title":"Service account enumerated and read a Kubernetes secret","attacks":[{"technique":{"uid":"T1552.007"}}]}}
```

Native wire format is the same content in a repo-owned envelope — see [docs/NATIVE_VS_OCSF.md](docs/NATIVE_VS_OCSF.md).

</details>

## Flagship: IAM departures remediation

The one shipped write path. Guarded, event-driven, cross-cloud, and dual-audited.

![IAM departures remediation showing the flagship write path in four stages. Stage one, select actionable scope before anything can act: the reconciler filters rehires and grace-window exceptions from HR sources and writes an S3 manifest. Stage two, start the guarded workflow: EventBridge launches a Step Function that gates a parser Lambda and a scoped worker Lambda, each with separate execution roles. Stage three, apply scoped writes into AWS, GCP, and Azure IAM via cross-account roles. Stage four, write a dual audit trail to DynamoDB and S3, then ingest back to HR so the next reconciler run verifies closure.](docs/images/iam-departures-architecture.svg)

- **scope first** — rehire and grace-window logic run in the reconciler before the manifest is written
- **separate principals** — EventBridge, Step Function, parser Lambda, worker Lambda each have their own execution role
- **dual audit** — DynamoDB + KMS-encrypted S3 for every write; ingest-back so the next run verifies closure
- **AWS-native on purpose** — equivalent GCP and Azure workflows keep the same control contract

Details: [skills/remediation/iam-departures-remediation/](skills/remediation/iam-departures-remediation/)

## Native vs OCSF

| Mode | When | What it is |
|---|---|---|
| `ocsf` | default for ingest and detect streams | OCSF 1.8 JSONL pinned to [`OCSF_CONTRACT.md`](skills/detection-engineering/OCSF_CONTRACT.md) |
| `native` | when you want repo fidelity without an envelope | repo-owned external wire format with stable UIDs |
| `bridge` | when you need both | interoperable fields with native context preserved |
| `canonical` | internal only | the normalization model between ingest and detect |

The `-ocsf` suffix means OCSF is the default, not the only output. Reference: [docs/NATIVE_VS_OCSF.md](docs/NATIVE_VS_OCSF.md) · [docs/CANONICAL_SCHEMA.md](docs/CANONICAL_SCHEMA.md) · [docs/NORMALIZATION_EXAMPLES.md](docs/NORMALIZATION_EXAMPLES.md)

## Install and trust

This repo is not primarily distributed as a PyPI package. Operators clone a tagged release, verify the signed SBOM set, and install only the dependency groups they need from [`pyproject.toml`](pyproject.toml). `uv.lock` is the ceiling, real installs are narrower.

- [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) — SBOM, signing, provenance
- [docs/CREDENTIAL_PROVENANCE.md](docs/CREDENTIAL_PROVENANCE.md) — workload identity first
- [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) — release gates

## Security posture

- **Read-only by default.** Write paths are HITL, audited, and dry-run-first.
- **No hardcoded secrets.** Workload identity and short-lived credentials only.
- **Official SDKs first**, repo-owned code second, canonical OSS only when required.
- **CI gates** validate skill contracts, integrity, the safe-skill bar, coverage, mypy, and SBOM generation.
- **Runtime isolation.** Wrappers cannot fork the skill model; they add transport only.

[SECURITY.md](SECURITY.md) · [SECURITY_BAR.md](SECURITY_BAR.md) · [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · [docs/RUNTIME_ISOLATION.md](docs/RUNTIME_ISOLATION.md)

## Compliance frameworks

CIS AWS / GCP / Azure Foundations · CIS Controls v8 · MITRE ATT&CK · NIST CSF 2.0 · SOC 2 TSC · ISO 27001:2022 · PCI DSS 4.0 · OWASP LLM Top 10 · OWASP MCP Top 10

Per-skill framework mapping: [docs/FRAMEWORK_MAPPINGS.md](docs/FRAMEWORK_MAPPINGS.md) · coverage report: [docs/FRAMEWORK_COVERAGE.md](docs/FRAMEWORK_COVERAGE.md)

## Where things stand

| Area | Shipped today | Planned |
|---|---|---|
| **Ingest** | 15 ingesters across AWS, GCP, Azure, K8s, Okta, Entra, Workspace, MCP | more identity and SaaS sources |
| **Discover** | 4 skills (AI BOM, cloud control evidence, control evidence, environment graph) | wider SaaS and infra evidence |
| **Detect** | 9 detectors tied to MITRE ATT&CK | credential stuffing, impossible travel, more MCP patterns |
| **Evaluate** | 7 benchmarks (82 checks) across CIS AWS/GCP/Azure, K8s, container, GPU, model serving | OCSF Compliance Finding class `2003` outputs |
| **Remediate** | IAM departures with HITL, dry-run, dual audit | broader remediation families as detection matures |
| **View** | SARIF, Mermaid attack flow | graph overlay, warehouse-ready converters |
| **Sinks** | Snowflake, ClickHouse, S3 | Security Lake, BigQuery |
| **Packs** | `lateral-movement`, `privilege-escalation-k8s` | broader warehouse dialect coverage |
| **Runners** | AWS S3/SQS, GCP GCS/PubSub, Azure Blob/EventGrid reference | more specialized runners on demand |

<details>
<summary><b>More diagrams and docs</b></summary>

**Visual set (6 diagrams, one per question):**
- [Hero banner](docs/images/hero-banner.svg) — what this is
- [Repository architecture](docs/images/repo-architecture.svg) — how it's shaped
- [Skill map](docs/images/skill-map.svg) — what's shipped
- [Agent and runtime integrations](docs/images/agent-integrations.svg) — how to run it
- [End-to-end skill flows](docs/images/end-to-end-skill-flows.svg) — how it composes
- [IAM departures architecture](docs/images/iam-departures-architecture.svg) — the flagship write path

**Operator and contributor docs:**
- [AGENTS.md](AGENTS.md) · [CLAUDE.md](CLAUDE.md) — cross-agent and Claude-specific repo contracts
- [skills/README.md](skills/README.md) — skill catalog
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — full design contract
- [docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md) · [docs/ROADMAP.md](docs/ROADMAP.md)
- [docs/SCHEMA_VERSIONING.md](docs/SCHEMA_VERSIONING.md) · [docs/SCHEMA_COVERAGE.md](docs/SCHEMA_COVERAGE.md)
- [docs/NORMALIZATION_REFERENCE.md](docs/NORMALIZATION_REFERENCE.md) · [docs/NORMALIZATION_EXAMPLES.md](docs/NORMALIZATION_EXAMPLES.md)
- [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md) · [docs/ERROR_CODES.md](docs/ERROR_CODES.md) · [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)

</details>

## Integration with agent-bom

This repo ships the security automations. [agent-bom](https://github.com/msaad00/agent-bom) provides continuous scanning and a unified graph. Use them together for detection + response.

## License

Apache 2.0. Security research is welcome — see [SECURITY.md](SECURITY.md) for coordinated disclosure.
