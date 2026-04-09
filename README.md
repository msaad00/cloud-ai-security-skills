# cloud-security

[![CI](https://github.com/msaad00/cloud-security/actions/workflows/ci.yml/badge.svg)](https://github.com/msaad00/cloud-security/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Scanned by agent-bom](https://img.shields.io/badge/scanned%20by-agent--bom-10b981)](https://github.com/msaad00/agent-bom)

Production-grade cloud security benchmarks and automation — CIS checks for AWS/GCP/Azure, model serving security, GPU cluster hardening, IAM remediation, and vulnerability response pipelines. Each skill is compliance-mapped, tested, and ready to deploy.

## Skills

| Skill | Scope | Checks | Description |
|-------|-------|--------|-------------|
| [cspm-aws-cis-benchmark](skills/cspm-aws-cis-benchmark/) | AWS | 18 | CIS AWS Foundations v3.0 — IAM, Storage, Logging, Networking |
| [cspm-gcp-cis-benchmark](skills/cspm-gcp-cis-benchmark/) | GCP | 25 | CIS GCP Foundations v3.0 + Vertex AI security |
| [cspm-azure-cis-benchmark](skills/cspm-azure-cis-benchmark/) | Azure | 24 | CIS Azure Foundations v2.1 + AI Foundry security |
| [model-serving-security](skills/model-serving-security/) | Any | 16 | Model endpoint auth, rate limiting, data egress, safety layers |
| [gpu-cluster-security](skills/gpu-cluster-security/) | Any | 13 | GPU runtime isolation, driver CVEs, InfiniBand, tenant isolation |
| [iam-departures-remediation](skills/iam-departures-remediation/) | Multi-cloud | — | Auto-remediate IAM for departed employees across 5 clouds |
| [vuln-remediation-pipeline](skills/vuln-remediation-pipeline/) | AWS | — | Auto-remediate supply chain vulns with EPSS triage |

## Architecture — IAM Departures Remediation

```mermaid
flowchart TD
    subgraph HR["HR Data Sources"]
        WD["Workday API"]
        SF["Snowflake SQL"]
        DB["Databricks Unity"]
        CH["ClickHouse SQL"]
    end

    subgraph SEC["AWS Security OU Account"]
        REC["Reconciler\nSHA-256 change detect"]
        S3["S3 Manifest\nKMS encrypted"]
        EB["EventBridge\nS3 PutObject trigger"]

        subgraph SFN["Step Function Pipeline"]
            L1["Parser Lambda\nvalidate · grace period · rehire filter"]
            L2["Worker Lambda\n13-step IAM cleanup"]
        end

        AUDIT["Audit Trail\nDynamoDB + S3"]
    end

    subgraph TGT["Target Accounts · STS AssumeRole"]
        T1["Revoke credentials"]
        T2["Strip permissions"]
        T3["Delete IAM user"]
    end

    subgraph CROSS["Cross-Cloud Workers"]
        AZ["Azure Entra\n6 steps"]
        GCP["GCP IAM\n4+2 steps"]
        SNF["Snowflake\n6 steps"]
        DBX["Databricks SCIM\n4 steps"]
    end

    WD & SF & DB & CH --> REC
    REC -->|change detected| S3
    S3 --> EB --> L1 --> L2
    L2 --> T1 --> T2 --> T3
    L2 --> AZ & GCP & SNF & DBX
    L2 --> AUDIT

    style HR fill:#1e293b,stroke:#475569,color:#e2e8f0
    style SEC fill:#0f172a,stroke:#334155,color:#e2e8f0
    style SFN fill:#164e63,stroke:#22d3ee,color:#e2e8f0
    style TGT fill:#1e3a5f,stroke:#60a5fa,color:#e2e8f0
    style CROSS fill:#1a2e35,stroke:#2dd4bf,color:#e2e8f0
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
    subgraph CONFIG["Serving Configuration"]
        GW["API Gateway"]
        K8S["K8s Manifests"]
        CLD["Cloud Serving\nSageMaker · Vertex · Azure ML"]
    end

    subgraph CHECKS["16 checks · 6 domains"]
        AUTH["Auth & RBAC"]
        RL["Rate Limiting"]
        EGR["Data Egress"]
        ISO["Container Isolation"]
        TLS["TLS & Network"]
        SAF["Safety Layers"]
    end

    GW & K8S & CLD --> AUTH & RL & EGR & ISO & TLS & SAF
    AUTH & RL & EGR & ISO & TLS & SAF --> OUT["JSON / Console"]

    style CONFIG fill:#1e293b,stroke:#475569,color:#e2e8f0
    style CHECKS fill:#164e63,stroke:#22d3ee,color:#e2e8f0
```

## Architecture — GPU Cluster Security

```mermaid
flowchart LR
    subgraph CLUSTER["GPU Cluster Configuration"]
        PODS["Pods & Containers"]
        NODES["GPU Nodes\nDrivers · CUDA"]
        IB["InfiniBand / RDMA"]
        NS["Namespaces & Quotas"]
    end

    subgraph CHECKS["13 checks · 6 domains"]
        RT["Runtime Isolation"]
        DRV["Driver & CUDA"]
        NET["Network Segmentation"]
        STO["Storage & SHM"]
        TEN["Tenant Isolation"]
        OBS["Observability"]
    end

    PODS --> RT
    NODES --> DRV
    IB --> NET
    NS --> TEN & STO

    RT & DRV & NET & STO & TEN & OBS --> OUT["JSON / Console"]

    style CLUSTER fill:#1e293b,stroke:#475569,color:#e2e8f0
    style CHECKS fill:#164e63,stroke:#22d3ee,color:#e2e8f0
```

## Architecture — Vulnerability Remediation Pipeline

```mermaid
flowchart TD
    SCAN["Scan Input\nSARIF / JSON"]
    S3["S3 Findings\nKMS encrypted"]
    EB["EventBridge"]

    subgraph SFN["Step Function"]
        TRIAGE["Triage Lambda\nEPSS + KEV + CVSS"]
        PATCH["Patcher Lambda"]
    end

    P0["P0 · KEV / CVSS 9+\n1h SLA"]
    P1["P1 · CVSS 7+ EPSS 0.7+\n4h SLA"]
    P2["P2 · CVSS 4+ / EPSS 0.3+\n72h SLA"]

    subgraph FIX["Remediation"]
        DEP["Dependency Upgrade\n7 ecosystems"]
        CRED["Credential Rotation"]
        QUAR["MCP Quarantine"]
    end

    AUDIT["Audit + Notify"]
    VERIFY["Re-scan"]

    SCAN --> S3 --> EB --> TRIAGE
    TRIAGE --> P0 & P1 & P2 --> PATCH
    PATCH --> DEP & CRED & QUAR --> AUDIT --> VERIFY

    style SFN fill:#164e63,stroke:#22d3ee,color:#e2e8f0
    style FIX fill:#1a2e35,stroke:#2dd4bf,color:#e2e8f0
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

This repo is scanned by [agent-bom](https://github.com/msaad00/agent-bom) in CI — dogfooding the scanner against its own security skills.

| CI Job | What |
|--------|------|
| Lint | ruff check + format |
| Test (IAM) | pytest — parser + worker Lambdas |
| Test (Model Serving) | pytest — 31 checks |
| Test (GPU Cluster) | pytest — 31 checks |
| **agent-bom scan** | **SAST + secret detection → SARIF → GitHub Security tab** |
| **agent-bom skills audit** | **SKILL.md security review → SARIF → GitHub Security tab** |
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

# Model serving security audit
python skills/model-serving-security/src/checks.py serving-config.json

# GPU cluster security audit
python skills/gpu-cluster-security/src/checks.py cluster-config.json

# Run tests
pip install pytest boto3 moto
cd skills/iam-departures-remediation && pytest tests/test_parser_lambda.py tests/test_worker_lambda.py -v

# Scan with agent-bom
pip install agent-bom
agent-bom skills scan skills/
agent-bom code skills/
```

## Integration with agent-bom

This repo provides the automations. [agent-bom](https://github.com/msaad00/agent-bom) provides continuous scanning:

| agent-bom Feature | Use Case |
|--------------------|----------|
| `cis_benchmark` | Built-in CIS for AWS/GCP/Azure/Snowflake |
| `code` | SAST scan of Lambda/skill source code |
| `skills scan` | Audit SKILL.md for security risks |
| `blast_radius` | Map impact of orphaned credentials |
| `compliance` | 15-framework compliance posture |
| `graph` | Visualize dependencies + attack paths |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE)
