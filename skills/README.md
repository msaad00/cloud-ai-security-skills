# Skills Catalog

Skills are grouped by **layered function**, not by vendor. Start with the problem you are solving, then pick the layer and skill that match it. If you want a guided entry point instead of a catalog, read [`docs/USE_CASES.md`](../docs/USE_CASES.md) first.

| Category | Question it answers | Default output format |
|---|---|---|
| [`ingestion/`](ingestion/) | "How do I normalize this raw source into a stable event stream?" | **OCSF 1.8** (native opt-in via `--output-format native`) |
| [`discovery/`](discovery/) | "What does this cloud / AI estate look like right now?" | **native / CycloneDX / bridge** (OCSF Inventory Info 5001 is too thin to force) |
| [`detection/`](detection/) | "What attack pattern does this event stream show?" | **OCSF Detection Finding 2004** (native opt-in) |
| [`evaluation/`](evaluation/) | "Does this posture or event stream meet a benchmark?" | **native** by default; OCSF Compliance Finding 2003 opt-in |
| [`view/`](view/) | "How should I render or export this OCSF output?" | **SARIF / Mermaid** — consumer of OCSF |
| [`remediation/`](remediation/) | "Something is wrong. How do I fix it safely?" | **native** (state change + audit record, not a finding) |
| [`output/`](output/) | "Where do these findings / evidence / audit rows persist?" | **pass-through** |

**OCSF is the SIEM interop wire format for ingest + detect — not the universal internal format.** See [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md#3-layer-model) §3.1 for the full applicability discussion.

Every shipped skill follows the [Anthropic skills guide](https://platform.claude.com/docs/en/build-with-claude/skills-guide): `SKILL.md`, `src/`, `tests/`, `REFERENCES.md`, and explicit `Use when...` / `Do NOT use...` routing language.

## ingestion/

Raw source formats to OCSF 1.8 JSONL.

| Skill | Scope |
|---|---|
| [`ingest-cloudtrail-ocsf`](ingestion/ingest-cloudtrail-ocsf/) | AWS CloudTrail |
| [`ingest-vpc-flow-logs-ocsf`](ingestion/ingest-vpc-flow-logs-ocsf/) | AWS VPC Flow Logs |
| [`ingest-vpc-flow-logs-gcp-ocsf`](ingestion/ingest-vpc-flow-logs-gcp-ocsf/) | GCP VPC Flow Logs |
| [`ingest-nsg-flow-logs-azure-ocsf`](ingestion/ingest-nsg-flow-logs-azure-ocsf/) | Azure NSG Flow Logs |
| [`ingest-guardduty-ocsf`](ingestion/ingest-guardduty-ocsf/) | AWS GuardDuty |
| [`ingest-security-hub-ocsf`](ingestion/ingest-security-hub-ocsf/) | AWS Security Hub |
| [`ingest-gcp-scc-ocsf`](ingestion/ingest-gcp-scc-ocsf/) | GCP Security Command Center |
| [`ingest-azure-defender-for-cloud-ocsf`](ingestion/ingest-azure-defender-for-cloud-ocsf/) | Azure Defender for Cloud |
| [`ingest-gcp-audit-ocsf`](ingestion/ingest-gcp-audit-ocsf/) | GCP Cloud Audit Logs |
| [`ingest-azure-activity-ocsf`](ingestion/ingest-azure-activity-ocsf/) | Azure Activity Logs |
| [`ingest-entra-directory-audit-ocsf`](ingestion/ingest-entra-directory-audit-ocsf/) | Microsoft Entra / Graph directory audit |
| [`ingest-okta-system-log-ocsf`](ingestion/ingest-okta-system-log-ocsf/) | Okta System Log |
| [`ingest-google-workspace-login-ocsf`](ingestion/ingest-google-workspace-login-ocsf/) | Google Workspace login audit |
| [`ingest-k8s-audit-ocsf`](ingestion/ingest-k8s-audit-ocsf/) | Kubernetes audit logs |
| [`ingest-mcp-proxy-ocsf`](ingestion/ingest-mcp-proxy-ocsf/) | MCP proxy activity |

## detection/

Deterministic OCSF-to-finding rules.

| Skill | MITRE |
|---|---|
| [`detect-lateral-movement`](detection/detect-lateral-movement/) | lateral movement / cross-cloud identity pivot + east-west traffic |
| [`detect-okta-mfa-fatigue`](detection/detect-okta-mfa-fatigue/) | Okta Verify push bombing / MFA fatigue |
| [`detect-credential-stuffing-okta`](detection/detect-credential-stuffing-okta/) | Okta credential stuffing / password spraying burst followed by successful sign-in (T1110.003) |
| [`detect-entra-credential-addition`](detection/detect-entra-credential-addition/) | successful Entra application or service-principal credential additions |
| [`detect-entra-role-grant-escalation`](detection/detect-entra-role-grant-escalation/) | successful Entra app-role grants to service principals |
| [`detect-google-workspace-suspicious-login`](detection/detect-google-workspace-suspicious-login/) | provider-marked suspicious Workspace login or repeated failures followed by success |
| [`detect-prompt-injection-mcp-proxy`](detection/detect-prompt-injection-mcp-proxy/) | suspicious prompt-injection language in MCP tool descriptions |
| [`detect-mcp-tool-drift`](detection/detect-mcp-tool-drift/) | T1195.001 |
| [`detect-privilege-escalation-k8s`](detection/detect-privilege-escalation-k8s/) | T1552.007, T1611, T1098, T1550.001 |
| [`detect-sensitive-secret-read-k8s`](detection/detect-sensitive-secret-read-k8s/) | secret access / K8s API misuse |

Shared wire-contract docs and frozen fixtures live under [`detection-engineering/`](detection-engineering/). That folder is a shared-assets namespace, not a skill layer.

## discovery/

Read-only inventory, graph, and AI BOM skills.

| Skill | Scope |
|---|---|
| [`discover-environment`](discovery/discover-environment/) | Multi-cloud discovery / graph overlay |
| [`discover-ai-bom`](discovery/discover-ai-bom/) | AI asset inventory → CycloneDX-aligned AI BOM |
| [`discover-control-evidence`](discovery/discover-control-evidence/) | Discovery artifact → PCI / SOC 2 technical evidence JSON |
| [`discover-cloud-control-evidence`](discovery/discover-cloud-control-evidence/) | Cross-cloud inventory → PCI / SOC 2 technical evidence JSON |

## evaluation/

Read-only posture and benchmark evaluation skills.

| Skill | Scope | Checks |
|---|---|---:|
| [`cspm-aws-cis-benchmark`](evaluation/cspm-aws-cis-benchmark/) | AWS | 18 |
| [`cspm-gcp-cis-benchmark`](evaluation/cspm-gcp-cis-benchmark/) | GCP | 7 |
| [`cspm-azure-cis-benchmark`](evaluation/cspm-azure-cis-benchmark/) | Azure | 6 |
| [`k8s-security-benchmark`](evaluation/k8s-security-benchmark/) | Kubernetes | 10 |
| [`container-security`](evaluation/container-security/) | Containers | 8 |
| [`model-serving-security`](evaluation/model-serving-security/) | AI model serving | 20 |
| [`gpu-cluster-security`](evaluation/gpu-cluster-security/) | GPU clusters | 13 |

## view/

OCSF outputs into review- or integration-friendly formats.

| Skill | Output |
|---|---|
| [`convert-ocsf-to-sarif`](view/convert-ocsf-to-sarif/) | SARIF |
| [`convert-ocsf-to-mermaid-attack-flow`](view/convert-ocsf-to-mermaid-attack-flow/) | Mermaid attack flow |

## remediation/

Active fix workflows with dry-run, audit, and guardrails.

| Skill | Scope |
|---|---|
| [`iam-departures-aws`](remediation/iam-departures-aws/) | AWS IAM cleanup for departed employees (per-cloud split for Azure/GCP/Snowflake/Databricks planned; library modules in `src/lambda_worker/clouds/`) |
| [`remediate-okta-session-kill`](remediation/remediate-okta-session-kill/) | Okta containment — revoke sessions + OAuth tokens after detect-okta-mfa-fatigue or detect-credential-stuffing-okta; dual-audit, deny-list, declared-incident gate |

## output/

Append-only persistence sinks for findings, evidence, and audit rows. Pure writers — no identity or cloud-config mutation, no re-shaping of the payload. Kept distinct from `remediation/` so the "skills are pure, edges have side effects" layering stays honest.

| Skill | Target |
|---|---|
| [`sink-s3-jsonl`](output/sink-s3-jsonl/) | Amazon S3 (immutable JSONL objects) |
| [`sink-snowflake-jsonl`](output/sink-snowflake-jsonl/) | Snowflake (staged COPY) |
| [`sink-clickhouse-jsonl`](output/sink-clickhouse-jsonl/) | ClickHouse (batched INSERT) |

## How to add a new skill

1. Pick the layer that matches the work.
2. Copy the nearest sibling in that layer as your reference layout.
3. Write `SKILL.md` with spec-compliant frontmatter. Name must be `^[a-z0-9-]+$`.
4. Lead the description with "Use when…" and close with "Do NOT use…".
5. Add tests. Detection, evaluation, and view skills should use the pinned OCSF contract and frozen fixtures where relevant.
6. Register the skill in the appropriate CI matrix and the top-level docs.
