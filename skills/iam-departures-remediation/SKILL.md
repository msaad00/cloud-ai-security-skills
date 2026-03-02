---
name: iam-departures-remediation
description: Auto-remediate IAM users created by departed employees — daily reconciliation with change-driven S3 export and EventBridge-triggered Step Function cleanup
version: 0.1.0
metadata:
  openclaw:
    requires:
      bins:
        - aws
      env:
        - AWS_ACCOUNT_ID
        - IAM_REMEDIATION_BUCKET
    optional_env:
      - SNOWFLAKE_ACCOUNT
      - SNOWFLAKE_USER
      - SNOWFLAKE_PASSWORD
      - DATABRICKS_HOST
      - DATABRICKS_TOKEN
      - CLICKHOUSE_HOST
      - CLICKHOUSE_USER
      - CLICKHOUSE_PASSWORD
      - WORKDAY_API_URL
      - WORKDAY_CLIENT_ID
      - WORKDAY_CLIENT_SECRET
      - IAM_GRACE_PERIOD_DAYS
      - IAM_CROSS_ACCOUNT_ROLE
      - IAM_AUDIT_DYNAMODB_TABLE
    emoji: "\U0001F6AA"
    homepage: https://github.com/msaad00/cloud-security
    source: https://github.com/msaad00/cloud-security
    license: Apache-2.0
    os:
      - darwin
      - linux
    file_reads: []
    file_writes:
      - "s3://${IAM_REMEDIATION_BUCKET}/departures/*.json"
      - "s3://${IAM_REMEDIATION_BUCKET}/departures/audit/*.json"
    network_endpoints:
      - url: "https://*.snowflakecomputing.com"
        purpose: "Query employee termination data from Workday tables replicated into Snowflake"
        auth: true
      - url: "https://*.cloud.databricks.com"
        purpose: "Query employee termination data from Workday tables replicated into Databricks"
        auth: true
      - url: "https://*.clickhouse.cloud"
        purpose: "Query employee termination data from ClickHouse"
        auth: true
      - url: "https://iam.amazonaws.com"
        purpose: "Enumerate and delete IAM users in target AWS accounts"
        auth: true
      - url: "https://sts.amazonaws.com"
        purpose: "AssumeRole into target accounts in the organization"
        auth: true
      - url: "https://s3.amazonaws.com"
        purpose: "Export change-detected remediation manifests and audit logs"
        auth: true
      - url: "https://dynamodb.amazonaws.com"
        purpose: "Write remediation audit records for compliance"
        auth: true
    telemetry: false
    persistence: true
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# iam-departures-remediation — Automated IAM Cleanup for Departed Employees

Reconciles HR termination data against IAM users daily, exports change-detected manifests to S3, and triggers Step Function remediation pipelines via EventBridge.

- **Multi-source HR ingestion** — Workday direct, Snowflake, Databricks, ClickHouse (wherever your HR data lands)
- **Rehire-safe** — Same-IAM reuse detected via last-activity timestamps; orphaned IAMs from rehires with new credentials are cleaned up
- **Already-deleted detection** — Skips IAM users that were manually removed, no false positives
- **Change-driven export** — Only pushes to S3 when the remediation table actually changes (SHA-256 row-level diff)
- **EventBridge + Step Functions** — S3 PutObject triggers a 2-Lambda pipeline: validate → remediate (Map state, 10 concurrent)
- **Full IAM dependency cleanup** — Keys, login profile, groups, policies, MFA, SSH keys, signing certs — then delete
- **Dual-write audit** — DynamoDB (operational queries) + S3 (immutable compliance archive) + warehouse ingest-back

## Threat Framework Mappings

This skill addresses identity persistence and credential lifecycle threats mapped across multiple security frameworks.

### MITRE ATT&CK

| Technique | ID | Relevance | Skill Coverage |
|-----------|-----|-----------|---------------|
| Valid Accounts: Cloud Accounts | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Departed employees retain active IAM credentials | Daily reconciliation detects and remediates |
| Account Manipulation: Additional Cloud Credentials | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Orphaned access keys persist after termination | All keys deactivated + deleted before user removal |
| Account Discovery: Cloud Account | [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | Enumeration of IAM users across org accounts | Cross-account STS AssumeRole validates existence |
| Account Access Removal | [T1531](https://attack.mitre.org/techniques/T1531/) | Remediation action: removing unauthorized access | Full IAM dependency cleanup pipeline |
| Unsecured Credentials | [T1552](https://attack.mitre.org/techniques/T1552/) | Dormant credentials exploitable by adversaries | Proactive cleanup within grace period |

### NIST Cybersecurity Framework (CSF 2.0)

| Function | Category | ID | Coverage |
|----------|----------|-----|---------|
| Protect | Identity Management & Access Control | PR.AC-1 | Credentials revoked upon termination |
| Protect | Access Control | PR.AC-4 | Permissions removed (groups, policies) |
| Detect | Continuous Monitoring | DE.CM-3 | Daily reconciliation detects stale IAM |
| Respond | Mitigation | RS.MI-2 | Automated remediation pipeline |

### CIS Controls v8

| Control | Description | Coverage |
|---------|-------------|---------|
| 5.3 | Disable Dormant Accounts | Core function — departed employees |
| 6.1 | Establish an Access Granting Process | Rehire detection prevents false revocation |
| 6.2 | Establish an Access Revoking Process | Automated revocation pipeline |
| 6.5 | Require MFA for Administrative Access | MFA devices cleaned up during remediation |

### SOC 2 (Trust Services Criteria)

| Criteria | Description | Coverage |
|----------|-------------|---------|
| CC6.1 | Logical and Physical Access Controls | IAM user lifecycle management |
| CC6.2 | Prior to Issuing System Credentials | Rehire detection validates before remediation |
| CC6.3 | Registration and Authorization | Deprovisioning on termination |

### OWASP Agentic Security

| Risk | Coverage |
|------|---------|
| Excessive Permissions | Removes all policies + group memberships |
| Credential Leakage | Deactivates + deletes all access keys |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     AWS Organization — Security OU                      │
│                                                                         │
│  ┌──────────────────────── Data Sources (Daily) ──────────────────────┐ │
│  │                                                                     │ │
│  │  ┌──────────┐  ┌───────────┐  ┌────────────┐  ┌────────────────┐  │ │
│  │  │ Workday  │  │ Snowflake │  │ Databricks │  │ ClickHouse     │  │ │
│  │  │  (API)   │  │ (table)   │  │ (table)    │  │ (table)        │  │ │
│  │  └────┬─────┘  └─────┬─────┘  └─────┬──────┘  └───────┬────────┘  │ │
│  │       └──────────────┴───────┬───────┴─────────────────┘           │ │
│  └──────────────────────────────┼─────────────────────────────────────┘ │
│                                 ▼                                       │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │  Reconciler  (src/reconciler/)                           │           │
│  │                                                          │           │
│  │  sources.py → DepartureRecord[] → change_detect.py       │           │
│  │                                    SHA-256 hash diff      │           │
│  │                                         │                │           │
│  │                                    changed? ──no──→ EXIT │           │
│  │                                         │ yes            │           │
│  │                                    export.py             │           │
│  └─────────────────────────────────────┬────────────────────┘           │
│                                        ▼                                │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │  S3 Bucket (KMS encrypted)                               │           │
│  │  s3://${IAM_REMEDIATION_BUCKET}/                         │           │
│  │    departures/YYYY-MM-DD.json     ← manifest             │           │
│  │    departures/.last_hash          ← change detection      │           │
│  │    departures/audit/*.json        ← remediation logs      │           │
│  └─────────────────────┬────────────────────────────────────┘           │
│                        │ PutObject (EventBridge notification ON)         │
│                        ▼                                                │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │  EventBridge Rule  (infra/eventbridge_rule.json)         │           │
│  │  Filter: source=aws.s3, prefix=departures/, suffix=.json │           │
│  └─────────────────────┬────────────────────────────────────┘           │
│                        ▼                                                │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │  Step Function  (infra/step_function.asl.json)           │           │
│  │                                                          │           │
│  │  ┌────────────────────────────────────────────────────┐  │           │
│  │  │ ParseManifest  (Lambda 1: lambda_parser/)          │  │           │
│  │  │                                                    │  │           │
│  │  │  1. Read S3 manifest                               │  │           │
│  │  │  2. Validate required fields                       │  │           │
│  │  │  3. Check grace period (default 7d)                │  │           │
│  │  │  4. Filter rehires (same-IAM vs orphaned)          │  │           │
│  │  │  5. Filter already-deleted IAMs                    │  │           │
│  │  │  6. STS AssumeRole → iam:GetUser (exists?)         │  │           │
│  │  │  7. Output: validated_entries[]                     │  │           │
│  │  └────────────────────┬───────────────────────────────┘  │           │
│  │                       ▼                                  │           │
│  │  ┌─────────── Map State (max 10 concurrent) ──────────┐  │           │
│  │  │                                                     │  │           │
│  │  │  ┌──────────────────────────────────────────────┐   │  │           │
│  │  │  │ RemediateSingleUser (Lambda 2: lambda_worker/)│   │  │           │
│  │  │  │                                              │   │  │           │
│  │  │  │  Per IAM user (order matters):               │   │  │  ┌──────┐│
│  │  │  │  1. Deactivate all access keys               │   │  │  │Target││
│  │  │  │  2. Delete all access keys                   │   │  │◄─┤ AWS  ││
│  │  │  │  3. Delete login profile (console)           │   │  │  │Accts ││
│  │  │  │  4. Remove from all groups                   │   │  │  └──────┘│
│  │  │  │  5. Detach all managed policies              │   │  │           │
│  │  │  │  6. Delete all inline policies               │   │  │           │
│  │  │  │  7. Deactivate + delete MFA devices          │   │  │           │
│  │  │  │  8. Delete signing certificates              │   │  │           │
│  │  │  │  9. Delete SSH public keys                   │   │  │           │
│  │  │  │  10. Delete service-specific credentials     │   │  │           │
│  │  │  │  11. Tag user (audit metadata)               │   │  │           │
│  │  │  │  12. DELETE IAM user                         │   │  │           │
│  │  │  │  13. Write audit → DynamoDB + S3             │   │  │           │
│  │  │  └──────────────────────────────────────────────┘   │  │           │
│  │  └─────────────────────────────────────────────────────┘  │           │
│  │                       ▼                                  │           │
│  │            GenerateSummary (Pass state)                   │           │
│  └──────────────────────────────────────────────────────────┘           │
│                        │                                                │
│                        ▼                                                │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │  Audit Ingest-Back (ETL)                                 │           │
│  │  DynamoDB/S3 audit → Snowflake/Databricks/ClickHouse     │           │
│  │  Updates remediation_status column, closes the loop       │           │
│  └──────────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
skills/iam-departures-remediation/
├── SKILL.md                                    # This file
├── src/
│   ├── reconciler/
│   │   ├── __init__.py                         # Module exports
│   │   ├── sources.py                          # Multi-source HR ingestion (Snowflake, DBX, CH, Workday)
│   │   ├── change_detect.py                    # SHA-256 row-level diff against S3 .last_hash
│   │   └── export.py                           # S3 manifest export with KMS encryption
│   ├── lambda_parser/
│   │   ├── __init__.py
│   │   └── handler.py                          # Lambda 1: validate, filter rehires, check IAM exists
│   └── lambda_worker/
│       ├── __init__.py
│       └── handler.py                          # Lambda 2: full IAM cleanup + delete + audit
├── infra/
│   ├── step_function.asl.json                  # ASL definition (ParseManifest → Map → Summary)
│   ├── eventbridge_rule.json                   # S3 ObjectCreated trigger
│   └── iam_policies/
│       ├── parser_execution_role.json          # Least-privilege for Lambda 1
│       ├── worker_execution_role.json          # Least-privilege for Lambda 2 (with Deny on protected users)
│       └── cross_account_remediation_role.json # Deployed to all target accounts via StackSets
└── tests/
    ├── test_reconciler.py                      # 15 tests: DepartureRecord, change detect, export
    ├── test_parser_lambda.py                   # 11 tests: validation, grace period, rehires
    └── test_worker_lambda.py                   # 8 tests: remediation steps, error handling
```

## Rehire Handling — All Caveats

The rehire logic operates at multiple levels (reconciler → parser → worker) with these scenarios:

| # | Scenario | Detection | Action |
|---|----------|-----------|--------|
| 1 | Employee terminated, not rehired | `is_rehire = false` | **REMEDIATE** — standard flow |
| 2 | Employee terminated, IAM already deleted by admin | `iam_deleted = true` | **SKIP** — log as already handled |
| 3 | Employee terminated → rehired → uses SAME IAM | `iam_last_used_at > rehire_date` | **SKIP** — active employee, same IAM still in use |
| 4 | Employee terminated → rehired → got NEW IAM, old IAM idle | `iam_last_used_at < rehire_date` AND `iam_created_at < rehire_date` | **REMEDIATE OLD IAM** — orphaned, employee has a new one |
| 5 | Employee terminated → rehired → new IAM record | `iam_created_at > rehire_date` | **SKIP** — this IS the employee's current IAM |
| 6 | Employee terminated → rehired → terminated AGAIN | Latest termination has `is_rehire = false` | **REMEDIATE** — they're gone again |
| 7 | Termination reversed within grace period | `terminated_at` within `IAM_GRACE_PERIOD_DAYS` | **SKIP** — wait for HR data to stabilize |
| 8 | Rehired but no IAM usage data available | `iam_last_used_at = NULL`, `iam_created_at < rehire_date` | **REMEDIATE** — conservative: assume orphaned |

Key implementation in `src/reconciler/sources.py:DepartureRecord.should_remediate()`:

```python
def should_remediate(self) -> bool:
    if self.iam_deleted:
        return False
    if self.terminated_at is None:
        return False
    if self.is_rehire and self.rehire_date:
        # Same IAM still in use after rehire → skip
        if self.iam_last_used_at and self.iam_last_used_at > self.rehire_date:
            return False
        # IAM created after rehire → this is their new IAM → skip
        if self.iam_created_at and self.iam_created_at > self.rehire_date:
            return False
        # Old IAM not used after rehire → orphaned → remediate
        return True
    return True
```

## IAM Deletion Order (AWS Requirement)

AWS will reject `iam:DeleteUser` unless ALL dependencies are removed first. The worker Lambda executes these in strict order:

```
1. Deactivate access keys  → iam:UpdateAccessKey (Status=Inactive)
2. Delete access keys      → iam:DeleteAccessKey
3. Delete login profile    → iam:DeleteLoginProfile
4. Remove from groups      → iam:RemoveUserFromGroup (all groups)
5. Detach managed policies → iam:DetachUserPolicy (all attached)
6. Delete inline policies  → iam:DeleteUserPolicy (all inline)
7. Deactivate MFA devices  → iam:DeactivateMFADevice
8. Delete virtual MFA      → iam:DeleteVirtualMFADevice
9. Delete signing certs    → iam:DeleteSigningCertificate
10. Delete SSH public keys → iam:DeleteSSHPublicKey
11. Delete service creds   → iam:DeleteServiceSpecificCredential
12. Tag user (audit trail) → iam:TagUser
13. DELETE user            → iam:DeleteUser
```

## Change Detection

The reconciler computes a SHA-256 hash of the full result set (sorted deterministically). Export to S3 only fires when the hash differs from the previous run.

Implementation in `src/reconciler/change_detect.py`:

```python
class ChangeDetector:
    HASH_KEY = "departures/.last_hash"

    def has_changed(self, records: list[DepartureRecord]) -> tuple[bool, str]:
        current_hash = self.compute_hash(records)  # SHA-256 of sorted JSON
        previous_hash = self.get_previous_hash()   # Read from S3
        return (current_hash != previous_hash, current_hash)
```

This prevents:
- Unnecessary Step Function executions (cost savings)
- Duplicate remediations (safety)
- EventBridge event storms (operational hygiene)

## Security Model

### Deployment: Organization Security OU

All infrastructure (Lambdas, Step Function, S3 bucket, DynamoDB table) runs in the **Security OU management account**. Cross-account access uses STS AssumeRole with org-scoped conditions.

### Least Privilege IAM Policies

Three IAM policies in `infra/iam_policies/`:

| Policy | Scope | Key Permissions |
|--------|-------|-----------------|
| `parser_execution_role.json` | Lambda 1 | `s3:GetObject`, `sts:AssumeRole`, `iam:GetUser` |
| `worker_execution_role.json` | Lambda 2 | Full IAM remediation + DynamoDB + S3 audit write |
| `cross_account_remediation_role.json` | Target accounts | IAM read/write scoped to `user/*`, explicit Deny on protected users |

### Protected User Deny

The worker role explicitly denies operations on protected accounts:

```json
{
  "Sid": "DenyProtectedUsers",
  "Effect": "Deny",
  "Action": "iam:*",
  "Resource": [
    "arn:aws:iam::*:user/root",
    "arn:aws:iam::*:user/break-glass-*",
    "arn:aws:iam::*:user/emergency-*",
    "arn:aws:iam::*:role/*"
  ]
}
```

### Organization-Scoped Trust

Cross-account role assumption is constrained by `aws:PrincipalOrgID` and `ArnLike` conditions — only the parser and worker Lambda roles in the Security OU account can assume the remediation role.

### Encryption

- S3 objects: `ServerSideEncryption: aws:kms`
- DynamoDB: Encryption at rest (AWS managed)
- All credentials in environment variables (Lambda encrypted at rest via KMS)

### Audit Trail (Dual-Write)

Every remediation action writes to:
1. **DynamoDB** — fast operational queries (who was deleted, when, by which Lambda invocation)
2. **S3** — immutable compliance archive (per-user JSON in `departures/audit/`)
3. **Ingest-back** — ETL pushes audit records back to the source warehouse, updating `remediation_status`

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `AWS_ACCOUNT_ID` | Security OU account ID (where Lambdas run) |
| `IAM_REMEDIATION_BUCKET` | S3 bucket for manifests + audit logs |

### Data Source (one required)

| Variable | Description |
|----------|-------------|
| `SNOWFLAKE_ACCOUNT` + `SNOWFLAKE_USER` + `SNOWFLAKE_PASSWORD` | Snowflake with Workday tables |
| `DATABRICKS_HOST` + `DATABRICKS_TOKEN` | Databricks with Workday tables |
| `CLICKHOUSE_HOST` + `CLICKHOUSE_USER` + `CLICKHOUSE_PASSWORD` | ClickHouse with Workday tables |
| `WORKDAY_API_URL` + `WORKDAY_CLIENT_ID` + `WORKDAY_CLIENT_SECRET` | Workday direct API |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `IAM_GRACE_PERIOD_DAYS` | `7` | Days after termination before remediation fires |
| `IAM_CROSS_ACCOUNT_ROLE` | `iam-remediation-role` | Role name in target accounts |
| `IAM_AUDIT_DYNAMODB_TABLE` | `iam-remediation-audit` | DynamoDB table for audit records |
| `SNOWFLAKE_HR_DATABASE` | `hr_db` | Snowflake database containing Workday data |
| `SNOWFLAKE_IAM_DATABASE` | `security_db` | Snowflake database containing IAM inventory |

## Cross-Cloud (Future)

The current implementation is AWS-focused. The architecture is designed for cross-cloud extension:

| Cloud | IAM Equivalent | Planned Support |
|-------|---------------|-----------------|
| AWS | IAM Users + Access Keys | **Implemented** |
| Azure | Entra ID (Azure AD) Users + Service Principals | Planned — Graph API |
| GCP | IAM Service Accounts + Keys | Planned — `iam.googleapis.com` |
| Snowflake | Users + Roles | Planned — `SHOW USERS` + `DROP USER` |
| Databricks | SCIM Users + PATs | Planned — Accounts API |

The reconciler `HRSource` abstraction and `DepartureRecord` schema are cloud-agnostic — only the worker Lambda needs cloud-specific implementations.

## Source & Verification

- **Source code**: https://github.com/msaad00/cloud-security (Apache-2.0)
- **Tests**: 34 unit tests covering all rehire scenarios, change detection, and remediation steps
- **No telemetry**: `telemetry: false` — zero tracking
- **Self-contained**: All logic runs in your AWS Organization, no external dependencies beyond HR data source
- **Auditable**: Every action logged to DynamoDB + S3 with full action trace
