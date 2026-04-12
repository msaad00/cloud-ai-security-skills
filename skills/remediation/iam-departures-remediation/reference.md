# Reference — IAM Departures Remediation

Detailed architecture, security model, IAM role definitions, framework mappings,
and cross-cloud roadmap.

---

## Secrets and Identity Guidance

- Treat env vars in examples as runtime injection points, not as a recommendation
  to store plaintext secrets in shell profiles or templates.
- Prefer AWS Secrets Manager, SSM Parameter Store, Vault, workload identity,
  Snowflake Storage Integration, and similar short-lived or managed-secret paths.
- Keep the event-driven trigger path intact: manifest lands in S3, EventBridge
  starts the Step Function, and the Step Function invokes parser and worker Lambdas.
- If you need a manual test, upload a manifest to the trigger bucket instead of
  calling the Step Function directly. That exercises the same production entrypoint.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AWS Organization — Security OU Account                    │
│                                                                             │
│  ┌─────────────────────── HR Data Sources (Daily) ────────────────────────┐ │
│  │                                                                         │ │
│  │  ┌──────────┐  ┌───────────────┐  ┌────────────┐  ┌────────────────┐  │ │
│  │  │ Workday  │  │  Snowflake    │  │ Databricks │  │  ClickHouse    │  │ │
│  │  │  (API)   │  │ (SQL / S.I.) │  │  (Unity)   │  │  (SQL)         │  │ │
│  │  └────┬─────┘  └──────┬───────┘  └─────┬──────┘  └───────┬────────┘  │ │
│  │       └───────────────┴────────┬────────┴─────────────────┘           │ │
│  └────────────────────────────────┼──────────────────────────────────────┘ │
│                                   ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Reconciler  (src/reconciler/)                                     │    │
│  │                                                                    │    │
│  │  sources.py ─→ DepartureRecord[]                                   │    │
│  │      │              │                                              │    │
│  │      │         should_remediate()                                  │    │
│  │      │              │                                              │    │
│  │      ▼              ▼                                              │    │
│  │  change_detect.py ─── SHA-256 hash ─── changed? ──no──→ EXIT      │    │
│  │                                           │ yes                    │    │
│  │                                      export.py                     │    │
│  └───────────────────────────────────────┬────────────────────────────┘    │
│                                          ▼                                 │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  S3 Bucket: ${IAM_REMEDIATION_BUCKET}                              │    │
│  │  Role ARN: arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/               │    │
│  │            iam-departures-s3-access-role                            │    │
│  │  Encryption: aws:kms (${KMS_KEY_ARN})                              │    │
│  │                                                                    │    │
│  │  departures/YYYY-MM-DD.json      ← remediation manifest            │    │
│  │  departures/.last_hash           ← change detection state           │    │
│  │  departures/audit/*.json         ← immutable compliance archive     │    │
│  └─────────────────────┬──────────────────────────────────────────────┘    │
│                        │ s3:ObjectCreated (EventBridge notification ON)     │
│                        ▼                                                   │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  EventBridge Rule                                                  │    │
│  │  Role ARN: arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/               │    │
│  │            iam-departures-events-role                               │    │
│  │  Filter: source=aws.s3, prefix=departures/, suffix=.json           │    │
│  │  Target: Step Function                                             │    │
│  └─────────────────────┬──────────────────────────────────────────────┘    │
│                        ▼                                                   │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Step Function: iam-departures-pipeline                            │    │
│  │  Role ARN: arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/               │    │
│  │            iam-departures-sfn-role                                  │    │
│  │                                                                    │    │
│  │  ┌──────────────────────────────────────────────────────────┐      │    │
│  │  │ State 1: ParseManifest                                   │      │    │
│  │  │ Lambda: iam-departures-parser                            │      │    │
│  │  │ Role ARN: arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/      │      │    │
│  │  │           iam-departures-parser-role                      │      │    │
│  │  │                                                          │      │    │
│  │  │  1. Read S3 manifest                                     │      │    │
│  │  │  2. Validate required fields (email, account_id, iam)    │      │    │
│  │  │  3. Check grace period (IAM_GRACE_PERIOD_DAYS, def: 7)   │      │    │
│  │  │  4. Filter rehires (same-IAM vs orphaned)                │      │    │
│  │  │  5. Filter already-deleted IAMs                          │      │    │
│  │  │  6. STS AssumeRole → iam:GetUser (verify exists)         │      │    │
│  │  │  Output: validated_entries[]                              │      │    │
│  │  └────────────────────┬─────────────────────────────────────┘      │    │
│  │                       ▼                                            │    │
│  │  ┌──────────── Map State (max 10 concurrent) ─────────────┐       │    │
│  │  │                                                         │       │    │
│  │  │  ┌───────────────────────────────────────────────────┐  │       │    │
│  │  │  │ State 2: RemediateSingleUser                      │  │       │    │
│  │  │  │ Lambda: iam-departures-worker                     │  │  ┌────┤    │
│  │  │  │ Role ARN: arn:aws:iam::${SECURITY_ACCOUNT_ID}:    │  │  │Tgt │    │
│  │  │  │           role/iam-departures-worker-role          │  │◄─┤AWS │    │
│  │  │  │                                                   │  │  │Acct│    │
│  │  │  │  Per IAM user (strict order):                     │  │  └────┘    │
│  │  │  │  1.  Deactivate access keys                       │  │            │
│  │  │  │  2.  Delete access keys                           │  │            │
│  │  │  │  3.  Delete login profile                         │  │            │
│  │  │  │  4.  Remove from all groups                       │  │            │
│  │  │  │  5.  Detach managed policies                      │  │            │
│  │  │  │  6.  Delete inline policies                       │  │            │
│  │  │  │  7.  Deactivate MFA devices                       │  │            │
│  │  │  │  8.  Delete virtual MFA devices                   │  │            │
│  │  │  │  9.  Delete signing certificates                  │  │            │
│  │  │  │  10. Delete SSH public keys                       │  │            │
│  │  │  │  11. Delete service-specific credentials          │  │            │
│  │  │  │  12. Tag user (remediated-at, terminated-at, ...) │  │            │
│  │  │  │  13. DELETE IAM user                              │  │            │
│  │  │  │  14. Write audit → DynamoDB + S3                  │  │            │
│  │  │  └───────────────────────────────────────────────────┘  │            │
│  │  └─────────────────────────────────────────────────────────┘            │
│  │                       ▼                                                 │
│  │            GenerateSummary (Pass state)                                  │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                        │                                                    │
│                        ▼                                                    │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │  Audit Ingest-Back (ETL)                                           │     │
│  │  DynamoDB/S3 → Snowflake/Databricks/ClickHouse                    │     │
│  │  Updates remediation_status column, closes the audit loop          │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  Cross-Account Role (deployed via StackSets to ALL member accounts):        │
│  arn:aws:iam::${TARGET_ACCOUNT_ID}:role/iam-remediation-role                │
│  Trust: Only Security OU Lambda roles, scoped by aws:PrincipalOrgID         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## IAM Role Definitions

### 1. Lambda Parser Execution Role

**Role ARN**: `arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/iam-departures-parser-role`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadManifestFromS3",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}/departures/*"
    },
    {
      "Sid": "AssumeRoleInTargetAccounts",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/${IAM_CROSS_ACCOUNT_ROLE}",
      "Condition": {
        "StringEquals": { "aws:PrincipalOrgID": "${AWS_ORG_ID}" }
      }
    },
    {
      "Sid": "ValidateIAMUserExists",
      "Effect": "Allow",
      "Action": ["iam:GetUser"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:PrincipalOrgID": "${AWS_ORG_ID}" }
      }
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:${SECURITY_ACCOUNT_ID}:log-group:/aws/lambda/iam-departures-parser*"
    }
  ]
}
```

**Trust Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

### 2. Lambda Worker Execution Role

**Role ARN**: `arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/iam-departures-worker-role`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeRoleInTargetAccounts",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/${IAM_CROSS_ACCOUNT_ROLE}",
      "Condition": {
        "StringEquals": { "aws:PrincipalOrgID": "${AWS_ORG_ID}" }
      }
    },
    {
      "Sid": "IAMRemediationActions",
      "Effect": "Allow",
      "Action": [
        "iam:GetUser", "iam:DeleteUser",
        "iam:ListAccessKeys", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
        "iam:DeleteLoginProfile",
        "iam:ListGroupsForUser", "iam:RemoveUserFromGroup",
        "iam:ListAttachedUserPolicies", "iam:DetachUserPolicy",
        "iam:ListUserPolicies", "iam:DeleteUserPolicy",
        "iam:ListMFADevices", "iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice",
        "iam:ListSigningCertificates", "iam:DeleteSigningCertificate",
        "iam:ListSSHPublicKeys", "iam:DeleteSSHPublicKey",
        "iam:ListServiceSpecificCredentials", "iam:DeleteServiceSpecificCredential",
        "iam:TagUser"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:PrincipalOrgID": "${AWS_ORG_ID}" }
      }
    },
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
    },
    {
      "Sid": "WriteAuditToDynamoDB",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem"],
      "Resource": "arn:aws:dynamodb:${AWS_REGION}:${SECURITY_ACCOUNT_ID}:table/${IAM_AUDIT_DYNAMODB_TABLE}"
    },
    {
      "Sid": "WriteAuditToS3",
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}/departures/audit/*"
    },
    {
      "Sid": "KMSForEncryption",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "${KMS_KEY_ARN}",
      "Condition": {
        "StringEquals": { "kms:ViaService": "s3.${AWS_REGION}.amazonaws.com" }
      }
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:${SECURITY_ACCOUNT_ID}:log-group:/aws/lambda/iam-departures-worker*"
    }
  ]
}
```

### 3. Step Function Execution Role

**Role ARN**: `arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/iam-departures-sfn-role`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeLambdas",
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": [
        "arn:aws:lambda:${AWS_REGION}:${SECURITY_ACCOUNT_ID}:function:iam-departures-parser",
        "arn:aws:lambda:${AWS_REGION}:${SECURITY_ACCOUNT_ID}:function:iam-departures-worker"
      ]
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:${SECURITY_ACCOUNT_ID}:log-group:/aws/states/iam-departures-pipeline*"
    },
    {
      "Sid": "XRayTracing",
      "Effect": "Allow",
      "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
      "Resource": "*"
    }
  ]
}
```

**Trust Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "states.amazonaws.com" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "aws:SourceAccount": "${SECURITY_ACCOUNT_ID}" }
    }
  }]
}
```

### 4. EventBridge Rule Role

**Role ARN**: `arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/iam-departures-events-role`

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "StartStepFunction",
    "Effect": "Allow",
    "Action": "states:StartExecution",
    "Resource": "arn:aws:states:${AWS_REGION}:${SECURITY_ACCOUNT_ID}:stateMachine:iam-departures-pipeline"
  }]
}
```

**Trust Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "events.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

### 5. S3 Bucket Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}/*",
      "Condition": {
        "StringNotEquals": { "s3:x-amz-server-side-encryption": "aws:kms" }
      }
    },
    {
      "Sid": "DenyNonSSL",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}",
        "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "RestrictToSecurityAccount",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}",
        "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}/*"
      ],
      "Condition": {
        "StringNotEquals": { "aws:PrincipalAccount": "${SECURITY_ACCOUNT_ID}" }
      }
    }
  ]
}
```

### 6. Cross-Account Remediation Role

**Role ARN**: `arn:aws:iam::${TARGET_ACCOUNT_ID}:role/iam-remediation-role`

Deployed to all member accounts via CloudFormation StackSets.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadWrite",
      "Effect": "Allow",
      "Action": [
        "iam:GetUser", "iam:DeleteUser", "iam:TagUser",
        "iam:ListAccessKeys", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
        "iam:DeleteLoginProfile",
        "iam:ListGroupsForUser", "iam:RemoveUserFromGroup",
        "iam:ListAttachedUserPolicies", "iam:DetachUserPolicy",
        "iam:ListUserPolicies", "iam:DeleteUserPolicy",
        "iam:ListMFADevices", "iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice",
        "iam:ListSigningCertificates", "iam:DeleteSigningCertificate",
        "iam:ListSSHPublicKeys", "iam:DeleteSSHPublicKey",
        "iam:ListServiceSpecificCredentials", "iam:DeleteServiceSpecificCredential"
      ],
      "Resource": "arn:aws:iam::${TARGET_ACCOUNT_ID}:user/*"
    },
    {
      "Sid": "DenyProtectedUsers",
      "Effect": "Deny",
      "Action": "iam:*",
      "Resource": [
        "arn:aws:iam::${TARGET_ACCOUNT_ID}:user/root",
        "arn:aws:iam::${TARGET_ACCOUNT_ID}:user/break-glass-*",
        "arn:aws:iam::${TARGET_ACCOUNT_ID}:user/emergency-*",
        "arn:aws:iam::${TARGET_ACCOUNT_ID}:role/*"
      ]
    }
  ]
}
```

**Trust Policy** (org-scoped):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${SECURITY_ACCOUNT_ID}:root" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "aws:PrincipalOrgID": "${AWS_ORG_ID}" },
      "ArnLike": {
        "aws:PrincipalArn": [
          "arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/iam-departures-parser-role",
          "arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/iam-departures-worker-role"
        ]
      }
    }
  }]
}
```

---

## Snowflake Storage Integration

Alternative to direct Snowflake connector credentials — use a Snowflake Storage
Integration to read IAM inventory data exported to S3, or to unload HR data to
the remediation bucket.

See [infra/snowflake_integration.sql](infra/snowflake_integration.sql) for the
full setup script.

**IAM Role for Snowflake**: `arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/iam-departures-snowflake-role`

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}",
      "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}/snowflake-export/*"
    ]
  }]
}
```

**Trust Policy** (Snowflake external ID):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "${SNOWFLAKE_IAM_USER_ARN}" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "sts:ExternalId": "${SNOWFLAKE_EXTERNAL_ID}" }
    }
  }]
}
```

---

## Framework Mappings

### MITRE ATT&CK

| Technique | ID | Tactic | Relevance | Skill Coverage |
|-----------|----|--------|-----------|---------------|
| Valid Accounts: Cloud Accounts | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Persistence, Privilege Escalation | Departed employees retain active IAM credentials | Daily reconciliation detects and remediates stale accounts |
| Account Manipulation: Additional Cloud Credentials | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Persistence | Orphaned access keys persist after termination | All access keys deactivated + deleted before user removal |
| Account Discovery: Cloud Account | [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | Discovery | Enumeration of IAM users across org accounts | Cross-account STS AssumeRole validates existence before action |
| Account Access Removal | [T1531](https://attack.mitre.org/techniques/T1531/) | Impact | Remediation action: removing unauthorized access | Full 13-step IAM dependency cleanup pipeline |
| Unsecured Credentials | [T1552](https://attack.mitre.org/techniques/T1552/) | Credential Access | Dormant credentials exploitable by adversaries | Proactive cleanup within configurable grace period |

### NIST Cybersecurity Framework (CSF 2.0)

| Function | Category | ID | Coverage |
|----------|----------|-----|---------|
| Protect | Identity Management & Access Control | PR.AC-1 | Credentials revoked upon termination detection |
| Protect | Access Control | PR.AC-4 | Permissions removed (groups, policies, MFA) |
| Detect | Continuous Monitoring | DE.CM-3 | Daily reconciliation detects stale IAM users |
| Respond | Mitigation | RS.MI-2 | Automated remediation via Step Function pipeline |

### CIS Controls v8

| Control | Description | Coverage |
|---------|-------------|---------|
| 5.3 | Disable Dormant Accounts | Core function — departed employee accounts |
| 6.1 | Establish an Access Granting Process | Rehire detection prevents false revocation |
| 6.2 | Establish an Access Revoking Process | Automated 13-step revocation pipeline |
| 6.5 | Require MFA for Administrative Access | MFA devices cleaned up during remediation |

### SOC 2 (Trust Services Criteria)

| Criteria | Description | Coverage |
|----------|-------------|---------|
| CC6.1 | Logical and Physical Access Controls | IAM user lifecycle management |
| CC6.2 | Prior to Issuing System Credentials | Rehire detection validates before remediation |
| CC6.3 | Registration and Authorization | Deprovisioning on termination |
| CC7.2 | Monitor System Components | Change detection + daily reconciliation |
| CC8.1 | Change Management | Audited pipeline with dual-write trail |

### OWASP Agentic Security

| Risk | Coverage |
|------|---------|
| Excessive Permissions | Removes all policies + group memberships |
| Credential Leakage | Deactivates + deletes all access keys |
| Insufficient Audit | Dual-write to DynamoDB + S3, warehouse ingest-back |

---

## Rehire Handling — All 8 Scenarios

| # | Scenario | Detection | Action |
|---|----------|-----------|--------|
| 1 | Employee terminated, not rehired | `is_rehire = false` | **REMEDIATE** |
| 2 | Employee terminated, IAM already deleted | `iam_deleted = true` | **SKIP** |
| 3 | Terminated → rehired → uses SAME IAM | `iam_last_used_at > rehire_date` | **SKIP** |
| 4 | Terminated → rehired → new IAM, old idle | `iam_last_used_at < rehire_date` | **REMEDIATE OLD** |
| 5 | Terminated → rehired → new IAM record | `iam_created_at > rehire_date` | **SKIP** |
| 6 | Terminated → rehired → terminated AGAIN | Latest termination, `is_rehire = false` | **REMEDIATE** |
| 7 | Termination reversed within grace period | Within `IAM_GRACE_PERIOD_DAYS` | **SKIP** |
| 8 | Rehired but no IAM usage data | `iam_last_used_at = NULL`, old IAM | **REMEDIATE** (conservative) |

Decision tree in `src/reconciler/sources.py:DepartureRecord.should_remediate()`.

---

## Change Detection

SHA-256 hash of the full remediation result set (sorted deterministically by
email + account_id). The hash is stored at `s3://${BUCKET}/departures/.last_hash`.

Export fires ONLY when hash differs from previous run. This prevents:
- Unnecessary Step Function executions (cost)
- Duplicate remediations (safety)
- EventBridge event storms (operational hygiene)

Implementation: `src/reconciler/change_detect.py`

---

## Cross-Cloud Identity Remediation

All cloud workers live in `src/lambda_worker/clouds/` and share a common
`RemediationResult` interface with per-step tracking.

| Cloud | Identity Type | SDK | Deletion Steps | Status |
|-------|--------------|-----|----------------|--------|
| AWS | IAM Users + Access Keys | `boto3` | 13 steps (keys → login → groups → policies → MFA → certs → SSH → svc creds → tag → delete) | **Implemented** |
| Azure | Entra ID Users | `msgraph-sdk` + `azure-identity` | 6 steps (revoke sessions → groups → app roles → OAuth grants → disable → delete) | **Implemented** |
| GCP | Service Accounts + Workspace Users | `google-cloud-iam` + `google-api-python-client` | 4 steps SA (disable → delete keys → remove IAM bindings → delete) / 2 steps Workspace | **Implemented** |
| Snowflake | Users + Roles | `snowflake-connector-python` | 6 steps (abort queries → disable → revoke roles → transfer ownership → drop → verify) | **Implemented** |
| Databricks | SCIM Users + PATs | `databricks-sdk` | 4 steps (revoke PATs → deactivate workspace → deactivate account → delete account) | **Implemented** |

### Cloud-Specific Gotchas

| Cloud | Gotcha | Impact |
|-------|--------|--------|
| Azure | `/$ref` is critical when removing group members — without it, the user object gets deleted | Data loss |
| Azure | Dynamic group members cannot be manually removed | Skip in loop |
| Azure | Soft delete: 30-day recycle bin | User can be restored |
| GCP | Deleting SA keys does NOT revoke already-issued short-lived tokens (1hr expiry) | Brief window of access |
| GCP | IAM policy read-modify-write has race conditions — always use etag | Policy corruption |
| GCP | IAM bindings can exist on projects, folders, org, AND individual resources | Must scan all |
| Snowflake | PUBLIC role cannot be revoked — it's implicit | Skip in revocation loop |
| Snowflake | DROP USER succeeds even with owned objects — they become orphaned | Transfer ownership FIRST |
| Snowflake | Snowsight worksheets become permanently inaccessible after DROP | No recovery |
| Databricks | SCIM provisioning from IdP may re-create deleted users on next sync | Deprovision from IdP first |
| Databricks | Account-level deletion cascades to ALL workspaces | Intentional but verify scope |

### Required Permissions per Cloud

**Azure Entra ID** (Microsoft Graph API — Application permissions):
- `User.ReadWrite.All`, `GroupMember.ReadWrite.All`
- `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`
- `Directory.Read.All`
- Entra ID role: User Administrator

**GCP** (IAM roles):
- `roles/iam.serviceAccountAdmin` (disable + delete SA)
- `roles/iam.serviceAccountKeyAdmin` (delete SA keys)
- `roles/resourcemanager.projectIamAdmin` (modify IAM policies)
- Workspace: Super Admin or User Management Admin

**Snowflake** (privileges):
- `USERADMIN` or `SECURITYADMIN` role
- `OWNERSHIP` on the user being remediated
- `SECURITYADMIN` for `REVOKE ROLE`

**Databricks** (admin roles):
- Workspace admin (PAT management + workspace-level SCIM)
- Account admin (account-level SCIM operations)

The reconciler's `HRSource` abstraction and `DepartureRecord` schema are
cloud-agnostic. Only the worker modules need cloud-specific remediation logic.

---

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `AWS_ACCOUNT_ID` | Security OU account ID |
| `AWS_REGION` | Deployment region (e.g., `us-east-1`) |
| `IAM_REMEDIATION_BUCKET` | S3 bucket name |
| `KMS_KEY_ARN` | KMS key ARN for S3 encryption |
| `AWS_ORG_ID` | AWS Organizations ID (for conditions) |

### Data Source (one required)

| Variable | Description |
|----------|-------------|
| `SNOWFLAKE_ACCOUNT` + `SNOWFLAKE_USER` + `SNOWFLAKE_PASSWORD` | Snowflake connector |
| `SNOWFLAKE_STORAGE_INTEGRATION` | Snowflake storage integration name (alternative) |
| `DATABRICKS_HOST` + `DATABRICKS_TOKEN` | Databricks SQL connector |
| `CLICKHOUSE_HOST` + `CLICKHOUSE_USER` + `CLICKHOUSE_PASSWORD` | ClickHouse connector |
| `WORKDAY_API_URL` + `WORKDAY_CLIENT_ID` + `WORKDAY_CLIENT_SECRET` | Workday RaaS API |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `IAM_GRACE_PERIOD_DAYS` | `7` | Days after termination before remediation |
| `IAM_CROSS_ACCOUNT_ROLE` | `iam-remediation-role` | Cross-account role name |
| `IAM_AUDIT_DYNAMODB_TABLE` | `iam-remediation-audit` | DynamoDB table name |
| `SNOWFLAKE_HR_DATABASE` | `hr_db` | Snowflake HR database |
| `SNOWFLAKE_IAM_DATABASE` | `security_db` | Snowflake IAM inventory database |
| `SECURITY_ACCOUNT_ID` | `${AWS_ACCOUNT_ID}` | Explicit Security OU account |
