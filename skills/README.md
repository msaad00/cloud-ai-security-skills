# Skills Catalog

Skills are grouped by **layered function**, not by vendor. An agent or operator chooses the layer that matches the job, then picks the skill inside that layer.

| Category | Question it answers | Output shape |
|---|---|---|
| [`ingestion/`](ingestion/) | "How do I normalize this raw source into OCSF?" | OCSF 1.8 JSONL |
| [`detection/`](detection/) | "What attack pattern does this event stream show?" | OCSF Detection Finding (class 2004) |
| [`evaluation/`](evaluation/) | "Does this posture or event stream meet a benchmark?" | Compliance / posture result |
| [`view/`](view/) | "How should I render or export this OCSF output?" | SARIF, Mermaid, other review formats |
| [`remediation/`](remediation/) | "Something is wrong. How do I fix it safely?" | Audited action + re-verification |

Every shipped skill follows the [Anthropic skills guide](https://platform.claude.com/docs/en/build-with-claude/skills-guide): `SKILL.md`, `src/`, `tests/`, `REFERENCES.md`, and explicit `Use when...` / `Do NOT use...` routing language.

Legacy folders remain for one release cycle as redirects:
- [`compliance-cis-mitre/`](compliance-cis-mitre/)
- [`ai-infra-security/`](ai-infra-security/)
- [`detection-engineering/`](detection-engineering/)

## ingestion/

Raw source formats to OCSF 1.8 JSONL.

| Skill | Scope |
|---|---|
| [`ingest-cloudtrail-ocsf`](ingestion/ingest-cloudtrail-ocsf/) | AWS CloudTrail |
| [`ingest-vpc-flow-logs-ocsf`](ingestion/ingest-vpc-flow-logs-ocsf/) | AWS VPC Flow Logs |
| [`ingest-guardduty-ocsf`](ingestion/ingest-guardduty-ocsf/) | AWS GuardDuty |
| [`ingest-security-hub-ocsf`](ingestion/ingest-security-hub-ocsf/) | AWS Security Hub |
| [`ingest-gcp-audit-ocsf`](ingestion/ingest-gcp-audit-ocsf/) | GCP Cloud Audit Logs |
| [`ingest-azure-activity-ocsf`](ingestion/ingest-azure-activity-ocsf/) | Azure Activity Logs |
| [`ingest-k8s-audit-ocsf`](ingestion/ingest-k8s-audit-ocsf/) | Kubernetes audit logs |
| [`ingest-mcp-proxy-ocsf`](ingestion/ingest-mcp-proxy-ocsf/) | MCP proxy activity |

## detection/

Deterministic OCSF-to-finding rules.

| Skill | MITRE |
|---|---|
| [`detect-lateral-movement-aws`](detection/detect-lateral-movement-aws/) | lateral movement / AWS session analytics |
| [`detect-mcp-tool-drift`](detection/detect-mcp-tool-drift/) | T1195.001 |
| [`detect-privilege-escalation-k8s`](detection/detect-privilege-escalation-k8s/) | T1552.007, T1611, T1098, T1550.001 |
| [`detect-sensitive-secret-read-k8s`](detection/detect-sensitive-secret-read-k8s/) | secret access / K8s API misuse |

Shared wire-contract docs and frozen fixtures still live under [`detection-engineering/`](detection-engineering/) during the transition window.

## evaluation/

Read-only posture, benchmark, and environment evaluation skills.

| Skill | Scope | Checks |
|---|---|---:|
| [`cspm-aws-cis-benchmark`](evaluation/cspm-aws-cis-benchmark/) | AWS | 18 |
| [`cspm-gcp-cis-benchmark`](evaluation/cspm-gcp-cis-benchmark/) | GCP | 7 |
| [`cspm-azure-cis-benchmark`](evaluation/cspm-azure-cis-benchmark/) | Azure | 6 |
| [`k8s-security-benchmark`](evaluation/k8s-security-benchmark/) | Kubernetes | 10 |
| [`container-security`](evaluation/container-security/) | Containers | 8 |
| [`model-serving-security`](evaluation/model-serving-security/) | AI model serving | 16 |
| [`gpu-cluster-security`](evaluation/gpu-cluster-security/) | GPU clusters | 13 |
| [`discover-environment`](evaluation/discover-environment/) | Multi-cloud discovery / graph overlay | n/a |

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
| [`iam-departures-remediation`](remediation/iam-departures-remediation/) | Multi-cloud IAM cleanup for departed employees |

## How to add a new skill

1. Pick the layer that matches the work.
2. Copy the nearest sibling in that layer as your reference layout.
3. Write `SKILL.md` with spec-compliant frontmatter. Name must be `^[a-z0-9-]+$`.
4. Lead the description with "Use when…" and close with "Do NOT use…".
5. Add tests. Detection, evaluation, and view skills should use the pinned OCSF contract and frozen fixtures where relevant.
6. Register the skill in the appropriate CI matrix and the top-level docs.
