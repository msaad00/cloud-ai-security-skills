---
name: iam-departures-remediation
description: >-
  Auto-remediate AWS IAM users belonging to departed employees. Reconciles HR
  termination data (Workday via Snowflake, Databricks, ClickHouse, or direct API)
  against IAM, exports change-detected manifests to S3, and triggers a Step Function
  pipeline that safely deletes IAM users with all dependencies. Use when the user
  mentions departed employees, IAM cleanup, termination remediation, offboarding
  automation, or stale credential removal.
license: Apache-2.0
compatibility: >-
  Requires AWS CLI, Python 3.11+, and boto3. Lambdas deploy to AWS. HR data
  source requires one of: Snowflake connector, Databricks SQL connector,
  clickhouse-connect, or httpx (Workday API).
metadata:
  author: msaad00
  version: 0.2.0
  frameworks:
    - MITRE ATT&CK
    - NIST CSF 2.0
    - CIS Controls v8
    - SOC 2
  cloud: aws
  cross_cloud_planned:
    - azure
    - gcp
    - snowflake
    - databricks
---

# IAM Departures Remediation

Automated IAM cleanup for departed employees with rehire-safe logic, change-driven
exports, and a 2-Lambda Step Function remediation pipeline.

Read [reference.md](reference.md) for detailed architecture, framework mappings,
IAM role ARN definitions, and security model. Read [examples.md](examples.md)
for deployment walkthroughs and usage scenarios.

## When to Use

- An employee is terminated and their AWS IAM user should be cleaned up
- Bulk offboarding after a layoff or reorganization
- Audit identifies stale IAM users tied to departed employees
- Compliance requires automated deprovisioning (SOC 2 CC6.3, CIS 5.3, NIST PR.AC-1)
- Security team wants to eliminate T1078.004 (Valid Accounts: Cloud Accounts) risk

## Pipeline Overview

```
HR Source (Workday/Snowflake/DBX/CH)
        │
        ▼
   Reconciler ──── change detected? ──no──→ EXIT
        │ yes
        ▼
   S3 Manifest (KMS encrypted)
        │ PutObject
        ▼
   EventBridge Rule
        │
        ▼
   Step Function
   ├── Lambda 1 (Parser): validate, grace period, rehire filter
   └── Lambda 2 (Worker): 13-step IAM cleanup → delete user
        │
        ▼
   Audit: DynamoDB + S3 + warehouse ingest-back
```

## Rehire Safety

The pipeline handles 8 rehire scenarios. Key rules:

1. **Rehired + same IAM in use** → SKIP (employee is active)
2. **Rehired + old IAM idle** → REMEDIATE (orphaned credential)
3. **IAM already deleted** → SKIP (no-op)
4. **Within grace period** → SKIP (HR correction window, default 7 days)
5. **Terminated again after rehire** → REMEDIATE

See `src/reconciler/sources.py:DepartureRecord.should_remediate()` for the
complete decision tree.

## IAM Deletion Order

AWS requires all dependencies removed before `iam:DeleteUser`. The worker
Lambda executes 13 steps in strict order:

1. Deactivate access keys
2. Delete access keys
3. Delete login profile (console access)
4. Remove from all groups
5. Detach all managed policies
6. Delete all inline policies
7. Deactivate MFA devices
8. Delete virtual MFA devices
9. Delete signing certificates
10. Delete SSH public keys
11. Delete service-specific credentials
12. Tag user with audit metadata
13. **Delete IAM user**

## AWS IAM Roles Required

Every component needs an IAM execution role. See [reference.md](reference.md)
for full policy documents and [infra/cloudformation.yaml](infra/cloudformation.yaml)
for deployable templates.

| Component | Role | Key Permissions |
|-----------|------|-----------------|
| Lambda 1 (Parser) | `iam-departures-parser-role` | `s3:GetObject`, `sts:AssumeRole`, `iam:GetUser` |
| Lambda 2 (Worker) | `iam-departures-worker-role` | Full IAM remediation, DynamoDB, S3, KMS |
| Step Function | `iam-departures-sfn-role` | `lambda:InvokeFunction` on both Lambdas |
| EventBridge | `iam-departures-events-role` | `states:StartExecution` on the Step Function |
| S3 Bucket | Bucket policy | Restrict to Security OU account only |
| Cross-Account | `iam-remediation-role` | IAM read/write in target accounts (StackSets) |

## Data Sources

Configure one HR data source via environment variables:

| Source | Required Env Vars |
|--------|-------------------|
| Snowflake | `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_PASSWORD` |
| Snowflake (Storage Integration) | `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_STORAGE_INTEGRATION` |
| Databricks | `DATABRICKS_HOST`, `DATABRICKS_TOKEN` |
| ClickHouse | `CLICKHOUSE_HOST`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` |
| Workday API | `WORKDAY_API_URL`, `WORKDAY_CLIENT_ID`, `WORKDAY_CLIENT_SECRET` |

## Security Principles

- **Least privilege**: Each role has only the permissions it needs
- **Defense in depth**: Deny policies on protected users (root, break-glass-*, emergency-*)
- **Zero trust**: Cross-account access scoped by `aws:PrincipalOrgID`
- **Encryption**: S3 KMS, DynamoDB encryption at rest, Lambda env var encryption
- **Audit trail**: Dual-write to DynamoDB + S3, ingest-back to source warehouse
- **Deployment**: All infra in Organization Security OU management account

## Project Structure

```
skills/iam-departures-remediation/
├── SKILL.md                    # This file (skill definition)
├── reference.md                # Detailed architecture + framework mappings
├── examples.md                 # Deployment walkthroughs
├── src/
│   ├── reconciler/
│   │   ├── sources.py          # Multi-source HR ingestion
│   │   ├── change_detect.py    # SHA-256 row-level diff
│   │   └── export.py           # S3 manifest export (KMS)
│   ├── lambda_parser/
│   │   └── handler.py          # Lambda 1: validate + filter
│   └── lambda_worker/
│       ├── handler.py          # Lambda 2: AWS 13-step cleanup
│       └── clouds/             # Cross-cloud workers
│           ├── azure_entra.py  # Entra ID: 6-step (msgraph-sdk)
│           ├── gcp_iam.py      # GCP: SA 4-step + Workspace 2-step
│           ├── snowflake_user.py # Snowflake: 6-step (SQL DDL)
│           └── databricks_scim.py # Databricks: 4-step (SCIM API)
├── infra/
│   ├── cloudformation.yaml     # Full stack (roles, Lambda, SFN, S3, DDB)
│   ├── cross_account_stackset.yaml # Org-wide role via StackSets
│   ├── step_function.asl.json  # ASL definition
│   ├── eventbridge_rule.json   # S3 trigger
│   ├── snowflake_integration.sql
│   └── iam_policies/           # Individual policy documents
└── tests/                      # 59 unit tests
```

## Deployment Options

Deploy with CloudFormation or Terraform — both produce identical infrastructure:

```bash
# CloudFormation
aws cloudformation deploy \
  --template-file infra/cloudformation.yaml \
  --stack-name iam-departures-remediation \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides OrgId=o-abc123def4 ...

# Terraform
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars  # edit with your values
terraform init && terraform plan && terraform apply
```

| IaC | Path | Resources |
|-----|------|-----------|
| CloudFormation | `infra/cloudformation.yaml` | Full stack (S3, KMS, DDB, Lambda, SFN, EventBridge, 4 IAM roles) |
| Terraform | `infra/terraform/main.tf` | Same resources, HCL format |
| StackSets | `infra/cross_account_stackset.yaml` | Org-wide cross-account remediation role |

## MITRE ATT&CK Coverage

| Technique | ID | How This Skill Addresses It |
|-----------|-----|---------------------------|
| Valid Accounts: Cloud | T1078.004 | Daily reconciliation detects + remediates |
| Additional Cloud Creds | T1098.001 | All access keys deactivated + deleted |
| Cloud Account Discovery | T1087.004 | Cross-account STS validates IAM existence |
| Account Access Removal | T1531 | Full dependency cleanup pipeline |
| Unsecured Credentials | T1552 | Proactive cleanup within grace period |

## CIS Benchmark Cross-Reference

This skill directly remediates findings flagged by CIS benchmarks:

| CIS Control | Benchmark | What This Skill Remediates |
|------------|-----------|---------------------------|
| 1.3 — Credentials unused 45+ days | CIS AWS v3.0 | Deletes departed-employee access keys + console access |
| 1.4 — Access keys rotated 90 days | CIS AWS v3.0 | Removes keys entirely (stronger than rotation) |
| 5.3 — Disable/remove unused accounts | CIS Controls v8 | Full 13-step cleanup + deletion |
| 6.1 — Establish access granting process | CIS Controls v8 | Automated deprovisioning tied to HR data |
| 6.2 — Establish access revoking process | CIS Controls v8 | Event-driven pipeline, < 24h from termination |
| 6.5 — Require MFA | CIS Controls v8 | Deactivates + deletes orphaned MFA devices |

> **Workflow**: Run `cspm-aws-cis-benchmark` to identify stale credentials → this skill automatically remediates them. The two skills work together — detection + response.
