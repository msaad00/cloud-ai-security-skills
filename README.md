<p align="center">
  <img src="https://img.shields.io/badge/Security-Automation-blue?style=for-the-badge&logo=amazon-aws&logoColor=white" alt="Security Automation"/>
  <img src="https://img.shields.io/badge/Zero_Trust-Defense_in_Depth-green?style=for-the-badge&logo=shield&logoColor=white" alt="Zero Trust"/>
  <img src="https://img.shields.io/badge/License-Apache_2.0-orange?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">cloud-security</h1>

<p align="center">
  <strong>Reusable security automation skills for AI agents</strong><br/>
  Enterprise-grade identity remediation across AWS, Azure, GCP, Snowflake, and Databricks
</p>

<p align="center">
  <a href="#skills">Skills</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#security-model">Security Model</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#compliance">Compliance</a>
</p>

---

## Skills

| Skill | Description | Clouds | Status |
|:------|:------------|:-------|:-------|
| [iam-departures-remediation](skills/iam-departures-remediation/) | Auto-remediate IAM users for departed employees | AWS, Azure, GCP, Snowflake, Databricks | Active |

Each skill follows the [Agent Skills](https://agentskills.io) standard — invocable by Claude Code, Cursor, and other AI agents via `SKILL.md`.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security OU Account                          │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────────┐ │
│  │ Workday  │    │Snowflake │    │   Databricks / ClickHouse  │ │
│  │   API    │    │   SQL    │    │         SQL / API          │ │
│  └────┬─────┘    └────┬─────┘    └──────────┬─────────────────┘ │
│       │               │                     │                   │
│       └───────────────┼─────────────────────┘                   │
│                       ▼                                         │
│              ┌─────────────────┐                                │
│              │   Reconciler    │ SHA-256 row-level change       │
│              │  (Python 3.11)  │ detection + rehire safety      │
│              └────────┬────────┘                                │
│                       │ change detected                         │
│                       ▼                                         │
│              ┌─────────────────┐                                │
│              │   S3 Manifest   │ KMS-SSE encrypted              │
│              │   (JSON)        │ Versioned + lifecycle           │
│              └────────┬────────┘                                │
│                       │ PutObject event                         │
│                       ▼                                         │
│              ┌─────────────────┐                                │
│              │  EventBridge    │ Pattern: s3://*/departures/*   │
│              │    Rule         │                                │
│              └────────┬────────┘                                │
│                       │ StartExecution                          │
│                       ▼                                         │
│         ┌──────────────────────────┐                            │
│         │     Step Function        │ X-Ray + CloudWatch         │
│         │  ┌────────────────────┐  │                            │
│         │  │ Lambda 1: Parser   │  │ Validate, grace period,   │
│         │  │                    │  │ rehire filter              │
│         │  └─────────┬──────────┘  │                            │
│         │            │             │                            │
│         │  ┌─────────▼──────────┐  │                            │
│         │  │ Lambda 2: Worker   │──┼──→ Cross-account STS      │
│         │  │ (13-step cleanup)  │  │    AssumeRole per target  │
│         │  └─────────┬──────────┘  │                            │
│         └────────────┼─────────────┘                            │
│                      │                                          │
│         ┌────────────▼─────────────┐                            │
│         │     Audit Trail          │                            │
│         │  DynamoDB + S3 + ingest  │                            │
│         │  back to warehouse       │                            │
│         └──────────────────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ Target   │  │ Target   │  │ Target   │
  │ Account  │  │ Account  │  │ Account  │
  │ (StackSet│  │ (StackSet│  │ (StackSet│
  │  role)   │  │  role)   │  │  role)   │
  └──────────┘  └──────────┘  └──────────┘
```

## Cross-Cloud Identity Remediation

Each cloud has a purpose-built worker with cloud-native SDKs and deletion orders:

| Cloud | Steps | SDK | Key Gotcha |
|:------|:-----:|:----|:-----------|
| **AWS** | 13 | `boto3` | Dependencies must be removed before `DeleteUser` |
| **Azure Entra ID** | 6 | `msgraph-sdk` | Group removal requires `/$ref` endpoint |
| **GCP IAM** | 4+2 | `google-cloud-iam` | IAM policy etag race conditions on concurrent updates |
| **Snowflake** | 6 | `snowflake-connector` | `PUBLIC` role cannot be revoked; ownership transfer per object type |
| **Databricks** | 4 | `databricks-sdk` | Account-level deletion cascades to all workspaces |

<details>
<summary><strong>AWS — 13-step deletion order</strong></summary>

1. Deactivate access keys
2. Delete access keys
3. Delete login profile (console)
4. Remove from all groups
5. Detach managed policies
6. Delete inline policies
7. Deactivate MFA devices
8. Delete virtual MFA devices
9. Delete signing certificates
10. Delete SSH public keys
11. Delete service-specific credentials
12. Tag user with audit metadata
13. **Delete IAM user**

</details>

<details>
<summary><strong>Azure Entra ID — 6-step remediation</strong></summary>

1. Revoke all sign-in sessions
2. Remove group memberships (via `/$ref`)
3. Remove app role assignments
4. Revoke OAuth2 permission grants
5. Disable user account
6. **Delete user**

</details>

<details>
<summary><strong>GCP — Service Account (4) + Workspace User (2)</strong></summary>

**Service Account:**
1. Disable service account
2. Delete user-managed keys (skip `SYSTEM_MANAGED`)
3. Remove IAM bindings across projects (etag-aware)
4. **Delete service account**

**Workspace User:**
1. Remove IAM bindings
2. **Delete user** (via Admin SDK)

</details>

<details>
<summary><strong>Snowflake — 6-step SQL DDL</strong></summary>

1. Abort active queries (`SELECT SYSTEM$CANCEL_ALL_QUERIES`)
2. Disable user (`ALTER USER ... SET DISABLED = TRUE`)
3. Revoke all roles (skip `PUBLIC` — cannot be revoked)
4. Transfer ownership per object type with `COPY CURRENT GRANTS`
5. Drop user (`DROP USER IF EXISTS`)
6. Verify dropped (`SHOW USERS LIKE`)

</details>

<details>
<summary><strong>Databricks — 4-step SCIM API</strong></summary>

1. Revoke personal access tokens
2. Deactivate workspace user (SCIM `PATCH active=false`)
3. Deactivate account user
4. **Delete account user** (cascades to all workspaces)

</details>

## Security Model

Every design decision follows **zero trust**, **defense in depth**, and **least privilege**:

```
┌─ Trust Boundaries ──────────────────────────────────────────────┐
│                                                                 │
│  DENY by default                                                │
│  ├── Protected users: root, break-glass-*, emergency-*          │
│  ├── Protected resources: IAM roles (never touched)             │
│  └── Cross-account: scoped by aws:PrincipalOrgID               │
│                                                                 │
│  Encryption everywhere                                          │
│  ├── S3: KMS-SSE (aws:kms) + deny unencrypted uploads          │
│  ├── DynamoDB: encryption at rest                               │
│  ├── Lambda: env var encryption via KMS                         │
│  └── Transit: TLS 1.2+ enforced (deny non-SSL)                 │
│                                                                 │
│  Audit trail (dual-write)                                       │
│  ├── DynamoDB: every remediation action with timestamp          │
│  ├── S3: JSON audit logs with lifecycle to Glacier              │
│  └── Warehouse: ingest-back for compliance reporting            │
│                                                                 │
│  Input validation + sanitization                                │
│  ├── All queries use parameterized values (never f-string SQL)  │
│  ├── IAM usernames validated against ^[\w+=,.@-]{1,64}$         │
│  ├── Account IDs validated against ^[0-9]{12}$                  │
│  └── Org IDs validated against ^o-[a-z0-9]{10,32}$             │
│                                                                 │
│  Rehire safety (8 scenarios)                                    │
│  ├── Active employee → SKIP                                     │
│  ├── Rehired + same IAM in use → SKIP                          │
│  ├── Rehired + old IAM idle → REMEDIATE                        │
│  ├── Within grace period (7d default) → SKIP                   │
│  └── Terminated after rehire → REMEDIATE                       │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Deploy the stack

```bash
aws cloudformation deploy \
  --template-file skills/iam-departures-remediation/infra/cloudformation.yaml \
  --stack-name iam-departures \
  --parameter-overrides \
      RemediationBucketName=my-org-iam-remediation \
      KMSKeyArn=arn:aws:kms:us-east-1:111122223333:key/... \
      OrgId=o-abc123 \
  --capabilities CAPABILITY_NAMED_IAM
```

### 2. Deploy cross-account roles (all member accounts)

```bash
aws cloudformation create-stack-set \
  --stack-set-name iam-remediation-cross-account \
  --template-body file://skills/iam-departures-remediation/infra/cross_account_stackset.yaml \
  --parameters ParameterKey=SecurityAccountId,ParameterValue=111122223333 \
               ParameterKey=OrgId,ParameterValue=o-abc123 \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false
```

### 3. Configure HR data source

```bash
# Snowflake (recommended for Snowflake orgs)
export SNOWFLAKE_ACCOUNT=myorg.us-east-1
export SNOWFLAKE_STORAGE_INTEGRATION=iam_departures_integration

# Or: Databricks, ClickHouse, Workday API
# See skills/iam-departures-remediation/SKILL.md for all options
```

### 4. Invoke via AI agent

```
"Find and remediate IAM users for all employees terminated in the last 30 days"
```

The skill auto-discovers the pipeline and executes with dry-run safety by default.

## Compliance

| Framework | Control | Coverage |
|:----------|:--------|:---------|
| **MITRE ATT&CK** | T1078.004, T1098.001, T1087.004, T1531, T1552 | Detect + remediate cloud account persistence |
| **NIST CSF 2.0** | PR.AC-1, PR.AC-6, DE.CM-3, RS.RP-1 | Identity lifecycle, access control, monitoring |
| **CIS Controls v8** | 5.3, 6.1, 6.2 | Account provisioning, authorization, deprovisioning |
| **SOC 2** | CC6.1, CC6.2, CC6.3 | Logical access, user provisioning, role removal |
| **OWASP Agentic** | AGA-01, AGA-04, AGA-07 | Least privilege, credential hygiene, audit trail |

## Project Structure

```
cloud-security/
├── README.md                                    # This file
└── skills/
    └── iam-departures-remediation/
        ├── SKILL.md                             # Agent skill definition
        ├── reference.md                         # Architecture + IAM policies
        ├── examples.md                          # Deployment walkthroughs
        ├── src/
        │   ├── reconciler/                      # HR data ingestion + change detection
        │   ├── lambda_parser/                   # Lambda 1: validate + filter
        │   └── lambda_worker/                   # Lambda 2: 13-step cleanup
        │       └── clouds/                      # Cross-cloud workers
        │           ├── azure_entra.py           # Entra ID (6-step)
        │           ├── gcp_iam.py               # GCP SA + Workspace
        │           ├── snowflake_user.py         # Snowflake SQL DDL (6-step)
        │           └── databricks_scim.py        # Databricks SCIM (4-step)
        ├── infra/
        │   ├── cloudformation.yaml              # Full deployable stack
        │   ├── cross_account_stackset.yaml      # Org-wide StackSets role
        │   └── snowflake_integration.sql        # Storage integration + tasks
        └── tests/                               # 84 unit tests
```

## License

Apache 2.0
