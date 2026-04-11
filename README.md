# cloud-security

[![CI](https://github.com/msaad00/cloud-security/actions/workflows/ci.yml/badge.svg)](https://github.com/msaad00/cloud-security/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Scanned by agent-bom](https://img.shields.io/badge/scanned_by-agent--bom-164e63)](https://github.com/msaad00/agent-bom)

**OCSF-native detection engineering and posture for cloud and AI infrastructure.** Heavy focus on clusters, containers, Kubernetes, GPUs, model serving, and the AI supply chain — and traditional VMs and cloud control planes alongside.

Architecture is layered: per-source ingestion skills normalise raw logs to **OCSF 1.8** on the wire, then detection skills emit OCSF Detection Findings (class 2004) with MITRE ATT&CK inside `finding_info.attacks[]`, and evaluation skills produce OCSF Compliance Findings (class 2003) mapped to CIS, NIST CSF, ISO 27001, and SOC 2. Skills compose via stdin/stdout pipes — no shared library, no single mega-skill, no vendor connectors. Each layer is independently testable, independently deployable, and independently scoped to least-privilege IAM.

Every skill is built to the same eleven-principle [Security Bar](SECURITY_BAR.md): read-only by default, agentless, least-privilege, defense in depth, closed-loop, secure by design, secure code, secure secrets, no telemetry, human-in-the-loop for destructive actions, and explicit guardrails against rogue or self-escalating skill behaviour.

Each skill is a standalone Python bundle following [Anthropic's skill spec](https://platform.claude.com/docs/en/build-with-claude/skills-guide) — `SKILL.md` with trigger phrases and a `Do NOT use…` clause, `src/`, `tests/`, golden fixtures, `REFERENCES.md` pointing at the official source documentation. Skills run from the CLI, in CI, or via any agent that reads `SKILL.md` (Claude Desktop, Cursor, Codex, Cortex, Windsurf).

```bash
# Detection pipeline (OCSF on the wire, Unix-style composition)
python skills/detection-engineering/ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python skills/detection-engineering/detect-privilege-escalation-k8s/src/detect.py \
  > findings.ocsf.jsonl
```

## Security & trust

This is a security tool. Trustworthiness is the first feature, not an afterthought. The repo is held to the [SECURITY_BAR.md](SECURITY_BAR.md) — eleven principles, every skill graded against every principle in a per-skill matrix.

| | What this means |
|---|---|
| **Read-only by default** | Posture and detection skills NEVER call write APIs. Remediation skills isolate the write path behind explicit IAM grants and require dry-run as the default. |
| **Agentless** | No daemons, no in-cluster sidecars, no continuously running processes. Skills are short-lived Python scripts that read what is already there. |
| **Least privilege** | Each skill documents the EXACT IAM / RBAC permissions it needs in `REFERENCES.md`. The set is minimised to what the skill cannot operate without. |
| **Defense in depth** | A single failed control never owns the whole story. Posture, detection, remediation, audit, and verification all run in parallel and back each other up. |
| **Closed loop** | Every workflow has a verification step: detect → finding → action → audit row → re-verify. Drift is itself a detection. |
| **OCSF on the wire** | All ingest and detect skills speak OCSF 1.8 JSONL. No bespoke shapes. MITRE ATT&CK lives inside `finding_info.attacks[]`. |
| **Secure by design** | Security is a first-class input to the skill's architecture, not a bolt-on. Read-only is the default, write paths are opt-in, every IAM grant is scoped, every input is parsed defensively, every output is validated against a schema. |
| **Secure code** | Defensive parsing on every input boundary. No `eval`/`exec`/`pickle.loads` on untrusted data. SQL via parameterised queries only. `bandit` runs in CI. |
| **Secure secrets, tokens, env vars** | No hardcoded credentials anywhere. Secrets come from cloud secret stores. Tokens are short-lived. Logs scrub credentials before emitting. CI greps for AKIA / `sk-` / `ghp_` patterns. |
| **No telemetry** | No skill phones home. No SDK clients to external services beyond what the cloud-native APIs the skill scans require. Findings stay local unless the operator explicitly forwards them. |
| **HITL, no rogue behaviour** | A skill never escalates its own privileges, never adds itself to allow-lists, never asks the agent to bypass a guardrail, never invokes a sibling skill it wasn't explicitly composed with. Destructive actions require a human-approved trigger and a HITL gate (grace periods, deny lists, dry-run defaults). |

**Validation & verification:**
- Every detection skill is tested against frozen OCSF golden fixtures so a refactor that loses coverage fails CI
- Every ingest skill emits exactly the OCSF wire shape pinned in [`OCSF_CONTRACT.md`](skills/detection-engineering/OCSF_CONTRACT.md)
- An end-to-end integration test in [`tests/integration/`](tests/integration/) pipes raw logs through the full ingest → detect chain and asserts the output matches the frozen golden findings
- `ruff check` + `ruff format --check` + `bandit` + hardcoded-secret grep all run on every PR
- Every skill has a [`REFERENCES.md`](skills/) listing the official documentation, schemas, and IAM policies it relies on — no opaque dependencies, no fabricated APIs

See [SECURITY.md](SECURITY.md) for the disclosure policy, [SECURITY_BAR.md](SECURITY_BAR.md) for the per-principle verification matrix, and [ARCHITECTURE.md](ARCHITECTURE.md) for the layered architecture diagram (Sources → Ingestion → OCSF → Detection / Evaluation → View → Remediation).

## Skills taxonomy

```
skills/
├── compliance-cis-mitre/          "Is this config/posture aligned with a published benchmark?"
├── remediation/                   "Something is wrong — fix it, gated and audited"
├── detection-engineering/         "What does an attack look like on this surface?"
└── ai-infra-security/             "AI-native surfaces: models, agents, GPU, topology"
```

See [`skills/README.md`](skills/README.md) for the full category index. The categories are functional, not organisational — a single incident (e.g. a leaked MCP credential) may touch a detection rule, a remediation pipeline, *and* a CIS control. Category = *what kind of work does this skill do*, not *which cloud*.

### compliance-cis-mitre/

| Skill | Scope | Checks | Description |
|-------|-------|--------|-------------|
| [cspm-aws-cis-benchmark](skills/compliance-cis-mitre/cspm-aws-cis-benchmark/) | AWS | 18 | CIS AWS Foundations v3.0 — IAM, Storage, Logging, Networking |
| [cspm-gcp-cis-benchmark](skills/compliance-cis-mitre/cspm-gcp-cis-benchmark/) | GCP | 7 | CIS GCP Foundations v3.0 — IAM, Cloud Storage, Networking |
| [cspm-azure-cis-benchmark](skills/compliance-cis-mitre/cspm-azure-cis-benchmark/) | Azure | 6 | CIS Azure Foundations v2.1 — Storage, Networking |
| [k8s-security-benchmark](skills/compliance-cis-mitre/k8s-security-benchmark/) | K8s | 10 | CIS Kubernetes — Pod security, RBAC, network policy |
| [container-security](skills/compliance-cis-mitre/container-security/) | Any | 8 | CIS Docker — Dockerfile best practices + runtime isolation |

### remediation/

| Skill | Scope | Description |
|-------|-------|-------------|
| [iam-departures-remediation](skills/remediation/iam-departures-remediation/) | Multi-cloud | Event-driven IAM cleanup for departed employees (HITL grace period, deny list, DLQ + SNS alerts) |

### detection-engineering/

Detection rules, ingestion pipelines, and threat hunts for cloud control planes, Kubernetes, and AI infrastructure. Every skill reads and writes **OCSF 1.8 JSONL** so they compose via stdin/stdout pipes. See [`skills/detection-engineering/README.md`](skills/detection-engineering/README.md) for the category contract and [`OCSF_CONTRACT.md`](skills/detection-engineering/OCSF_CONTRACT.md) for the field-level wire format.

**Ingestion** (raw log → OCSF API Activity `6003` or Application Activity `6002`):

| Skill | Source | OCSF class |
|---|---|---|
| [`ingest-cloudtrail-ocsf`](skills/detection-engineering/ingest-cloudtrail-ocsf/) | AWS CloudTrail | API Activity 6003 |
| [`ingest-gcp-audit-ocsf`](skills/detection-engineering/ingest-gcp-audit-ocsf/) | GCP Cloud Audit Logs | API Activity 6003 |
| [`ingest-azure-activity-ocsf`](skills/detection-engineering/ingest-azure-activity-ocsf/) | Azure Activity Logs | API Activity 6003 |
| [`ingest-k8s-audit-ocsf`](skills/detection-engineering/ingest-k8s-audit-ocsf/) | `kube-apiserver` audit logs | API Activity 6003 |
| [`ingest-mcp-proxy-ocsf`](skills/detection-engineering/ingest-mcp-proxy-ocsf/) | agent-bom MCP proxy | Application Activity 6002 |

**Detection** (OCSF events → OCSF Detection Finding `2004` + MITRE ATT&CK inside `finding_info.attacks[]`):

| Skill | Input | MITRE techniques |
|---|---|---|
| [`detect-mcp-tool-drift`](skills/detection-engineering/detect-mcp-tool-drift/) | OCSF Application Activity (MCP) | T1195.001 |
| [`detect-privilege-escalation-k8s`](skills/detection-engineering/detect-privilege-escalation-k8s/) | OCSF API Activity (K8s) | T1552.007, T1611, T1098, T1550.001 |

### ai-infra-security/

| Skill | Scope | Checks | Description |
|-------|-------|--------|-------------|
| [model-serving-security](skills/ai-infra-security/model-serving-security/) | Any | 16 | Model endpoint auth, rate limiting, egress, safety layers |
| [gpu-cluster-security](skills/ai-infra-security/gpu-cluster-security/) | Any | 13 | GPU runtime isolation, driver CVEs, InfiniBand, tenant isolation |
| [discover-environment](skills/ai-infra-security/discover-environment/) | Multi-cloud | — | Map cloud resources to a security graph with MITRE ATT&CK/ATLAS overlays |

## Architecture — IAM Departures Remediation

Six numbered stations across two deployment domains, one forward path, one dashed drift loop. Every destructive step happens inside the VPC-isolated Step Function; the reconciler stays stateless outside it.

<p align="center">
  <img src="docs/images/iam-departures-architecture.svg" alt="IAM Departures Remediation architecture: HR sources and Reconciler in the AWS Corporate Security OU; Parser and Worker Lambdas in a VPC-isolated Step Function; five cloud targets; dual-write audit trail; dashed verification loop back to the reconciler." width="100%"/>
</p>

**What's intentionally not shown** (to keep the diagram legible):
- **Failure path** — Lambda async failures → SQS DLQ (`iam-departures-dlq`); Step Function `FAILED`/`TIMED_OUT`/`ABORTED` → EventBridge → SNS (`iam-departures-alerts`). See [`SKILL.md`](skills/remediation/iam-departures-remediation/SKILL.md).
- **DLQ replay** — stuck executions re-drive through the same EventBridge rule. The pipeline is idempotent.
- **Extensibility** — new consumers (SIEM forwarder, Slack, secondary region) are additional EventBridge targets. No reconciler or Lambda changes.

## Architecture — CSPM CIS Benchmarks

Closed loop: scan → finding → ticket/PR → fix → re-scan verifies the same control_id is now `pass`. Findings keep their `control_id` so the verification run can prove the gap closed.

```mermaid
flowchart LR
    subgraph CLOUD["Cloud Account · read-only"]
        IAM["IAM / Identity"]
        STR["Storage"]
        LOG["Logging + Audit"]
        NET["Networking"]
        AI["AI / ML Services"]
    end

    CHK["checks.py\nread-only SDK calls\nno write permissions"]
    OUT["Findings\nJSON · SARIF · Console"]
    SIEM["SIEM / Ticketing\nGitHub code scanning\nJira · Splunk · Datadog"]
    FIX["Remediation\nIaC PR · console fix\nor exception with TTL"]
    VERIFY["Next scan run\ncontrol_id == pass\nor drift flagged"]

    IAM & STR & LOG & NET & AI --> CHK --> OUT --> SIEM --> FIX --> VERIFY
    VERIFY -. re-scan .-> CHK

    style CLOUD fill:#1e293b,stroke:#475569,color:#e2e8f0
    style CHK fill:#164e63,stroke:#22d3ee,color:#e2e8f0
    style OUT fill:#1e3a5f,stroke:#60a5fa,color:#e2e8f0
    style SIEM fill:#1e1b4b,stroke:#a78bfa,color:#e2e8f0
    style FIX fill:#1a2e35,stroke:#2dd4bf,color:#e2e8f0
    style VERIFY fill:#172554,stroke:#3b82f6,color:#e2e8f0
```

## Architecture — Vulnerability Remediation Pipeline

Closed loop: scan → triage → patch → audit → re-scan verifies the CVE is no longer present *and* the package version matches the expected fix version.

```mermaid
flowchart LR
    SCAN["Scan Findings\nSARIF / JSON"]
    TRIAGE["Triage\nEPSS · KEV · CVSS\nP0→P3 SLAs"]
    FIX["Remediate\nUpgrade · Rotate · Quarantine"]
    AUDIT["Audit + Verify\nDDB log + S3 evidence"]
    RESCAN["Re-scan\nCVE absent · version pinned"]

    SCAN --> TRIAGE --> FIX --> AUDIT --> RESCAN
    RESCAN -. drift .-> SCAN

    style SCAN fill:#1e293b,stroke:#475569,color:#e2e8f0
    style TRIAGE fill:#164e63,stroke:#22d3ee,color:#e2e8f0
    style FIX fill:#1a2e35,stroke:#2dd4bf,color:#e2e8f0
    style AUDIT fill:#1e1b4b,stroke:#a78bfa,color:#e2e8f0
    style RESCAN fill:#172554,stroke:#3b82f6,color:#e2e8f0
```

## Security Model

```mermaid
flowchart LR
    subgraph ZT["Zero Trust"]
        A1["Cross-account scoped\nby PrincipalOrgID"]
        A2["STS AssumeRole\nper account"]
        A3["VPC isolation"]
    end

    subgraph LP["Least Privilege"]
        B1["Parser: read-only"]
        B2["Worker: scoped write"]
        B3["CSPM: read-only"]
        B4["Model/GPU: read-only"]
    end

    subgraph DD["Defense in Depth"]
        C1["Deny policies on\nprotected accounts"]
        C2["KMS encryption\neverywhere"]
        C3["Dual audit trail\nDDB + S3"]
    end

    style ZT fill:#1e293b,stroke:#60a5fa,color:#e2e8f0
    style LP fill:#1a2e35,stroke:#2dd4bf,color:#e2e8f0
    style DD fill:#1e1b4b,stroke:#a78bfa,color:#e2e8f0
```

## Compliance Framework Mapping

| Framework | Controls | Skills |
|-----------|----------|--------|
| **CIS AWS Foundations v3.0** | 18 controls | cspm-aws |
| **CIS GCP Foundations v3.0** | 7 controls (subset) | cspm-gcp |
| **CIS Azure Foundations v2.1** | 6 controls (subset) | cspm-azure |
| **MITRE ATT&CK** | T1078, T1098, T1087, T1195.001, T1530, T1599 | iam-departures, detect-mcp-tool-drift |
| **NIST CSF 2.0** | PR.AC, PR.DS, DE.CM, DE.AE, RS.MI, ID.RA | All skills |
| **CIS Controls v8** | 5.3, 6.1, 6.2, 6.5, 7.1–7.4, 13.1, 16.1 | iam-departures |
| **SOC 2 TSC** | CC6.1–CC6.3, CC7.1 | iam-departures |
| **ISO 27001:2022** | A.5.15–A.8.24 | cspm-aws, cspm-gcp, cspm-azure |
| **PCI DSS 4.0** | 2.2, 7.1, 8.3, 10.1 | cspm skills |
| **OWASP MCP Top 10** | MCP-04 (supply chain compromise) | detect-mcp-tool-drift |

> CIS GCP and CIS Azure currently automate a curated subset of high-impact controls. The full benchmark coverage is tracked in each skill's `SKILL.md`. PRs that add controls are welcome — keep one check per function and one finding row per control.

## CI/CD Pipeline

| CI Job | What |
|--------|------|
| Lint | ruff check + format |
| Tests | pytest per skill |
| CloudFormation | `cfn-lint` validation on all `infra/*.yaml` |
| Terraform | `terraform validate` on `infra/terraform/` |
| Security | `bandit` + hardcoded-secret grep on `skills/*/src/` |
| **agent-bom** | `code` (AI components) · `skills scan` (skill audit) · `fs` (packages + CVEs) · **`iac` (CloudFormation + Terraform)** with SARIF upload to the GitHub Security tab |

The "Scanned by agent-bom" badge above is backed by that last row — every push to `main` runs all four agent-bom scans against the repo, and the IaC findings land in GitHub code scanning.

## Quick Start

```bash
git clone https://github.com/msaad00/cloud-security.git
cd cloud-security

# compliance-cis-mitre — CSPM CIS benchmarks (read-only)
pip install boto3 google-cloud-resource-manager azure-identity
python skills/compliance-cis-mitre/cspm-aws-cis-benchmark/src/checks.py   --region us-east-1
python skills/compliance-cis-mitre/cspm-gcp-cis-benchmark/src/checks.py   --project my-project
python skills/compliance-cis-mitre/cspm-azure-cis-benchmark/src/checks.py --subscription <sub-id>

# remediation — dry-run mode (no mutations)
python skills/remediation/iam-departures-remediation/src/lambda_parser/handler.py --dry-run examples/manifest.json

# detection-engineering — end-to-end pipe: raw MCP proxy → OCSF → Detection Finding
python skills/detection-engineering/ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python skills/detection-engineering/detect-mcp-tool-drift/src/detect.py \
  > findings.ocsf.jsonl

# Run all real-skill tests
pip install pytest boto3 moto
pytest skills/compliance-cis-mitre/cspm-aws-cis-benchmark/tests/     -v -o "testpaths=tests"
pytest skills/compliance-cis-mitre/cspm-gcp-cis-benchmark/tests/     -v -o "testpaths=tests"
pytest skills/compliance-cis-mitre/cspm-azure-cis-benchmark/tests/   -v -o "testpaths=tests"
pytest skills/remediation/iam-departures-remediation/tests/          -v -o "testpaths=tests"
pytest skills/detection-engineering/ingest-mcp-proxy-ocsf/tests/     -v -o "testpaths=tests"
pytest skills/detection-engineering/detect-mcp-tool-drift/tests/     -v -o "testpaths=tests"
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE)
