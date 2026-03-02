---
name: iam-departures-remediation
description: Auto-remediate IAM users for departed employees across AWS, Azure, GCP, Snowflake, and Databricks.
version: 0.3.0
license: Apache-2.0
author: msaad00
cloud: [aws, azure, gcp, snowflake, databricks]
compatibility: Python 3.11+, boto3, AWS CLI
frameworks: [MITRE ATT&CK, NIST CSF 2.0, CIS v8, SOC 2]
tests: 84
---

# IAM Departures Remediation

Automated IAM cleanup for departed employees with rehire-safe logic, change-driven
exports, and a Step Function remediation pipeline.

> **Invoke when:** departed employees, IAM cleanup, termination remediation,
> offboarding automation, stale credential removal

**Docs:** [reference.md](reference.md) (architecture, IAM policies, framework mappings) ·
[examples.md](examples.md) (deployment walkthroughs)

## When to Use

- An employee is terminated and their AWS IAM user should be cleaned up
- Bulk offboarding after a layoff or reorganization
- Audit identifies stale IAM users tied to departed employees
- Compliance requires automated deprovisioning (SOC 2 CC6.3, CIS 5.3, NIST PR.AC-1)
- Security team wants to eliminate T1078.004 (Valid Accounts: Cloud Accounts) risk

## Pipeline Overview

```
  ╔═══════════════════════════════════════════════════════════════╗
  ║  HR Source                                                    ║
  ║  Workday API │ Snowflake │ Databricks │ ClickHouse           ║
  ╚══════════╦════════════════════════════════════════════════════╝
             ║
             ▼
  ┌──────────────────────┐     ┌─────────┐
  │   Reconciler         │────▶│  EXIT   │  no changes
  │   SHA-256 row diff   │     └─────────┘
  │   + rehire safety    │
  └──────────┬───────────┘
             │ change detected
             ▼
  ┌──────────────────────┐
  │   S3 Manifest        │  KMS-SSE encrypted
  │   (JSON)             │  versioned + lifecycle
  └──────────┬───────────┘
             │ PutObject → EventBridge
             ▼
  ┌──────────────────────────────────────────┐
  │         Step Function                     │
  │  ┌────────────────────────────────────┐  │
  │  │  Lambda 1 — Parser                 │  │
  │  │  validate · grace period · rehire  │  │
  │  └───────────────┬────────────────────┘  │
  │                  │                        │
  │  ┌───────────────▼────────────────────┐  │
  │  │  Lambda 2 — Worker                 │  │
  │  │  AWS 13-step │ Azure 6 │ GCP 4+2  │  │
  │  │  Snowflake 6 │ Databricks 4       │  │
  │  └───────────────┬────────────────────┘  │
  └──────────────────┼───────────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────────┐
  │  Audit Trail                              │
  │  DynamoDB + S3 + warehouse ingest-back   │
  └──────────────────────────────────────────┘
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

## Cross-Cloud Remediation

| Cloud | Steps | SDK | Deletion Order |
|:------|:-----:|:----|:---------------|
| **AWS** | 13 | boto3 | Keys → Login → Groups → Policies → MFA → Certs → SSH → Tag → Delete |
| **Azure** | 6 | msgraph-sdk | Sessions → Groups → AppRoles → OAuth → Disable → Delete |
| **GCP** | 4+2 | google-cloud-iam | Disable SA → Keys → IAM Bindings → Delete |
| **Snowflake** | 6 | snowflake-connector | Queries → Disable → Roles → Ownership → Drop → Verify |
| **Databricks** | 4 | databricks-sdk | PATs → Workspace → Account → Delete |

See [reference.md](reference.md) for full deletion procedures and cloud-specific gotchas.

## IAM Roles

| Component | Role | Key Permissions |
|:----------|:-----|:----------------|
| Lambda 1 (Parser) | `iam-departures-parser-role` | `s3:GetObject`, `sts:AssumeRole`, `iam:GetUser` |
| Lambda 2 (Worker) | `iam-departures-worker-role` | Full IAM remediation, DynamoDB, S3, KMS |
| Step Function | `iam-departures-sfn-role` | `lambda:InvokeFunction` on both Lambdas |
| EventBridge | `iam-departures-events-role` | `states:StartExecution` on the Step Function |
| Cross-Account | `iam-remediation-role` | IAM read/write in targets (StackSets) |

Full policy documents: [reference.md](reference.md) ·
Deployable templates: [infra/cloudformation.yaml](infra/cloudformation.yaml)

## Data Sources

Configure one HR data source via environment variables:

| Source | Required Env Vars |
|--------|-------------------|
| Snowflake | `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_PASSWORD` |
| Snowflake (Storage Integration) | `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_STORAGE_INTEGRATION` |
| Databricks | `DATABRICKS_HOST`, `DATABRICKS_TOKEN` |
| ClickHouse | `CLICKHOUSE_HOST`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` |
| Workday API | `WORKDAY_API_URL`, `WORKDAY_CLIENT_ID`, `WORKDAY_CLIENT_SECRET` |

## Security

> Zero trust · Defense in depth · Least privilege · Parameterized queries

| Principle | Implementation |
|:----------|:---------------|
| **Least privilege** | Each Lambda/SFN/EventBridge role scoped to exactly needed actions |
| **Defense in depth** | Explicit DENY on protected users: `root`, `break-glass-*`, `emergency-*` |
| **Zero trust** | Cross-account STS scoped by `aws:PrincipalOrgID` condition |
| **Encryption** | S3 KMS-SSE + deny unencrypted · DynamoDB at rest · Lambda env KMS |
| **Input validation** | IAM usernames `^[\w+=,.@-]{1,64}$` · Account IDs `^[0-9]{12}$` |
| **Audit trail** | Dual-write: DynamoDB + S3 JSON logs + warehouse ingest-back |
| **Rehire safety** | 8 scenarios with grace period (7d default) and activity checks |

## Project Structure

```
skills/iam-departures-remediation/
├── SKILL.md                        # Skill definition (Agent Skills standard)
├── reference.md                    # Architecture, IAM policies, framework mappings
├── examples.md                     # Deployment walkthroughs
├── src/
│   ├── reconciler/                 # HR data ingestion + change detection
│   │   ├── sources.py              #   Multi-source: Snowflake/DBX/CH/Workday
│   │   ├── change_detect.py        #   SHA-256 row-level diff
│   │   └── export.py               #   S3 manifest export (KMS)
│   ├── lambda_parser/              # Lambda 1: validate + filter
│   │   └── handler.py
│   └── lambda_worker/              # Lambda 2: remediation engine
│       ├── handler.py              #   AWS 13-step cleanup
│       └── clouds/                 #   Cross-cloud workers
│           ├── azure_entra.py      #     Entra ID (msgraph-sdk)
│           ├── gcp_iam.py          #     GCP SA + Workspace
│           ├── snowflake_user.py   #     Snowflake SQL DDL
│           └── databricks_scim.py  #     Databricks SCIM API
├── infra/
│   ├── cloudformation.yaml         # Full deployable stack
│   ├── cross_account_stackset.yaml # Org-wide StackSets role
│   └── snowflake_integration.sql   # Storage integration + tasks
└── tests/                          # 84 unit tests
```

## MITRE ATT&CK Coverage

| Technique | ID | How This Skill Addresses It |
|-----------|-----|---------------------------|
| Valid Accounts: Cloud | T1078.004 | Daily reconciliation detects + remediates |
| Additional Cloud Creds | T1098.001 | All access keys deactivated + deleted |
| Cloud Account Discovery | T1087.004 | Cross-account STS validates IAM existence |
| Account Access Removal | T1531 | Full dependency cleanup pipeline |
| Unsecured Credentials | T1552 | Proactive cleanup within grace period |
