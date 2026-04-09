# cloud-security

[![CI](https://github.com/msaad00/cloud-security/actions/workflows/ci.yml/badge.svg)](https://github.com/msaad00/cloud-security/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Scanned by agent-bom](https://img.shields.io/badge/scanned_by-agent--bom-164e63)](https://github.com/msaad00/agent-bom)

Production-grade cloud security benchmarks and automation — 10 skills, 159 tests, compliance-mapped to MITRE ATT&CK, NIST CSF, CIS, ISO 27001, and SOC 2.

Each skill is a standalone Python script with its own checks, tests, examples, and SKILL.md definition following [Anthropic's skill spec](https://docs.anthropic.com). Skills can be used directly from the CLI, integrated into CI/CD pipelines, or referenced by AI agents that read SKILL.md files (Claude Desktop, Cortex Code, etc.).

## Skills

| Skill | Scope | Checks | Description |
|-------|-------|--------|-------------|
| [cspm-aws-cis-benchmark](skills/cspm-aws-cis-benchmark/) | AWS | 18 | CIS AWS Foundations v3.0 — IAM, Storage, Logging, Networking |
| [cspm-gcp-cis-benchmark](skills/cspm-gcp-cis-benchmark/) | GCP | 25 | CIS GCP Foundations v3.0 + Vertex AI security |
| [cspm-azure-cis-benchmark](skills/cspm-azure-cis-benchmark/) | Azure | 24 | CIS Azure Foundations v2.1 + AI Foundry security |
| [model-serving-security](skills/model-serving-security/) | Any | 16 | Model endpoint auth, rate limiting, data egress, safety layers |
| [gpu-cluster-security](skills/gpu-cluster-security/) | Any | 13 | GPU runtime isolation, driver CVEs, InfiniBand, tenant isolation |
| [k8s-security-benchmark](skills/k8s-security-benchmark/) | Any | 10 | Pod security, RBAC, network policies, secrets, image pinning |
| [container-security](skills/container-security/) | Any | 8 | Dockerfile best practices, image security, runtime isolation |
| [discover-environment](skills/discover-environment/) | Multi-cloud | — | Map cloud resources to security graph with MITRE ATT&CK/ATLAS overlays |
| [iam-departures-remediation](skills/iam-departures-remediation/) | Multi-cloud | — | Auto-remediate IAM for departed employees across 5 clouds |
| [vuln-remediation-pipeline](skills/vuln-remediation-pipeline/) | AWS | — | Auto-remediate supply chain vulns with EPSS triage |

## Architecture — IAM Departures Remediation

```mermaid
flowchart LR
    HR["HR Sources\nWorkday · Snowflake\nDatabricks · ClickHouse"]
    REC["Reconciler\nSHA-256 diff"]
    SFN["Step Function\nParser → Worker"]
    TGT["IAM Cleanup\n13 steps · 5 clouds"]
    AUDIT["Audit\nDDB + S3"]

    HR --> REC --> SFN --> TGT --> AUDIT

    style HR fill:#1e293b,stroke:#475569,color:#e2e8f0
    style REC fill:#164e63,stroke:#22d3ee,color:#e2e8f0
    style SFN fill:#164e63,stroke:#22d3ee,color:#e2e8f0
    style TGT fill:#1e3a5f,stroke:#60a5fa,color:#e2e8f0
    style AUDIT fill:#1e1b4b,stroke:#a78bfa,color:#e2e8f0
```

## Architecture — CSPM CIS Benchmarks

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

    IAM & STR & LOG & NET & AI --> CHK

    CHK --> JSON["JSON"]
    CHK --> CON["Console"]
    CHK --> SARIF["SARIF"]

    style CLOUD fill:#1e293b,stroke:#475569,color:#e2e8f0
    style CHK fill:#164e63,stroke:#22d3ee,color:#e2e8f0
```

## Architecture — Model Serving Security

```mermaid
flowchart LR
    CONFIG["Serving Config\nAPI Gateway · K8s · Cloud ML"]
    BENCH["checks.py\n16 checks · 6 domains\nAuth · Rate Limit · Egress\nRuntime · TLS · Safety"]
    OUT["JSON / Console"]

    CONFIG --> BENCH --> OUT

    style CONFIG fill:#1e293b,stroke:#475569,color:#e2e8f0
    style BENCH fill:#164e63,stroke:#22d3ee,color:#e2e8f0
```

## Architecture — GPU Cluster Security

```mermaid
flowchart LR
    CLUSTER["Cluster Config\nPods · Nodes · InfiniBand\nNamespaces · Storage"]
    BENCH["checks.py\n13 checks · 6 domains\nRuntime · Driver · Network\nStorage · Tenant · Observability"]
    OUT["JSON / Console"]

    CLUSTER --> BENCH --> OUT

    style CLUSTER fill:#1e293b,stroke:#475569,color:#e2e8f0
    style BENCH fill:#164e63,stroke:#22d3ee,color:#e2e8f0
```

## Architecture — Vulnerability Remediation Pipeline

```mermaid
flowchart LR
    SCAN["Scan Findings\nSARIF / JSON"]
    TRIAGE["Triage\nEPSS · KEV · CVSS\nP0→P3 SLAs"]
    FIX["Remediate\nUpgrade · Rotate · Quarantine"]
    AUDIT["Audit + Verify"]

    SCAN --> TRIAGE --> FIX --> AUDIT

    style SCAN fill:#1e293b,stroke:#475569,color:#e2e8f0
    style TRIAGE fill:#164e63,stroke:#22d3ee,color:#e2e8f0
    style FIX fill:#1a2e35,stroke:#2dd4bf,color:#e2e8f0
    style AUDIT fill:#1e1b4b,stroke:#a78bfa,color:#e2e8f0
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
| **CIS GCP Foundations v3.0** | 20 + 5 Vertex AI | cspm-gcp |
| **CIS Azure Foundations v2.1** | 19 + 5 AI Foundry | cspm-azure |
| **MITRE ATT&CK** | T1078, T1098, T1087, T1195, T1203, T1530, T1599, T1610, T1611 | iam-departures, gpu-cluster |
| **MITRE ATLAS** | AML.T0010, T0024, T0025, T0042, T0048, T0051 | model-serving |
| **NIST CSF 2.0** | PR.AC, PR.DS, DE.CM, DE.AE, RS.MI, ID.RA | All skills |
| **CIS Controls v8** | 5.3, 6.1, 6.2, 6.5, 7.1–7.4, 8.2, 8.5, 13.1, 13.6, 16.1 | iam-departures, vuln-remediation, gpu-cluster |
| **SOC 2 TSC** | CC6.1–CC6.3, CC7.1 | iam-departures, vuln-remediation |
| **ISO 27001:2022** | A.5.15–A.8.24 | cspm-aws, cspm-gcp, cspm-azure |
| **PCI DSS 4.0** | 2.2, 7.1, 8.3, 10.1 | cspm skills |
| **OWASP LLM Top 10** | LLM-05, LLM-07, LLM-08 | vuln-remediation, model-serving |
| **OWASP MCP Top 10** | MCP-04 | vuln-remediation |

## CI/CD Pipeline

| CI Job | What |
|--------|------|
| Lint | ruff check + format |
| Tests | pytest per skill (IAM, model-serving, GPU, K8s, container, discover) |
| CloudFormation | cfn-lint validation |
| Terraform | terraform validate |
| Security | bandit + hardcoded secret grep |

## Quick Start

```bash
git clone https://github.com/msaad00/cloud-security.git
cd cloud-security

# AWS CIS benchmark
pip install boto3
python skills/cspm-aws-cis-benchmark/src/checks.py --region us-east-1

# Model serving security (with example config)
python skills/model-serving-security/src/checks.py skills/model-serving-security/examples/insecure-serving.json

# GPU cluster security (with example config)
python skills/gpu-cluster-security/src/checks.py skills/gpu-cluster-security/examples/insecure-cluster.json

# K8s security benchmark
python skills/k8s-security-benchmark/src/checks.py skills/k8s-security-benchmark/examples/secure-cluster.json

# Container security
python skills/container-security/src/checks.py skills/container-security/examples/secure-image.json

# Run tests
pip install pytest boto3 moto
pytest skills/model-serving-security/tests/ -v -o "testpaths=tests"
pytest skills/gpu-cluster-security/tests/ -v -o "testpaths=tests"
pytest skills/k8s-security-benchmark/tests/ -v -o "testpaths=tests"
pytest skills/container-security/tests/ -v -o "testpaths=tests"
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE)
