# Cloud Security Skills Collection

This repository contains production-ready cloud security automations structured as skills for AI agents.

## Repository structure

```
skills/
  iam-departures-remediation/   — Multi-cloud IAM cleanup for departed employees
  cspm-aws-cis-benchmark/       — CIS AWS Foundations v3.0 (18 checks)
  cspm-gcp-cis-benchmark/       — CIS GCP Foundations v3.0 (20 checks + 5 Vertex AI)
  cspm-azure-cis-benchmark/     — CIS Azure Foundations v2.1 (19 checks + 5 AI Foundry)
  model-serving-security/       — Model serving security benchmark (16 checks)
  gpu-cluster-security/         — GPU cluster security benchmark (13 checks)
  k8s-security-benchmark/       — Kubernetes security benchmark (10 checks)
  container-security/           — Container image + runtime security (8 checks)
  discover-environment/         — Cloud environment discovery with MITRE ATT&CK/ATLAS overlay
  vuln-remediation-pipeline/    — Auto-remediate supply chain vulnerabilities
```

## Conventions

- Each skill has a `SKILL.md` with frontmatter (name, description, license, compatibility, metadata, frameworks).
- Source code lives in `src/` within each skill directory.
- Infrastructure-as-code lives in `infra/` (CloudFormation, Terraform, StackSets).
- Tests live in `tests/` within each skill directory.
- All skills are Apache 2.0 licensed.
- Python 3.11+ required. Type hints used throughout.
- No hardcoded credentials. All secrets via environment variables or AWS Secrets Manager.

## Security model

- CSPM skills are read-only (no write permissions to cloud accounts).
- Remediation skills use least-privilege IAM with cross-account STS AssumeRole.
- Deny policies protect root, break-glass, and emergency accounts from deletion.
- All S3 artifacts are KMS-encrypted. DynamoDB tables use encryption at rest.

## Compliance frameworks referenced

MITRE ATT&CK, NIST CSF 2.0, CIS Controls v8, CIS AWS/GCP/Azure Foundations, SOC 2 TSC, ISO 27001:2022, PCI DSS 4.0, OWASP LLM Top 10, OWASP MCP Top 10.

## Running checks

```bash
# AWS CIS benchmark
pip install boto3
python skills/cspm-aws-cis-benchmark/src/checks.py --region us-east-1

# GCP CIS benchmark
pip install google-cloud-iam google-cloud-storage google-cloud-compute
python skills/cspm-gcp-cis-benchmark/src/checks.py --project my-project

# Azure CIS benchmark
pip install azure-identity azure-mgmt-authorization azure-mgmt-storage azure-mgmt-monitor azure-mgmt-network
python skills/cspm-azure-cis-benchmark/src/checks.py --subscription-id SUB_ID

# IAM departures tests
cd skills/iam-departures-remediation && pip install boto3 moto pytest && pytest tests/ -v
```

## Integration with agent-bom

This repo provides the security automations. [agent-bom](https://github.com/msaad00/agent-bom) provides continuous scanning and compliance validation. Use together for detection + response.
