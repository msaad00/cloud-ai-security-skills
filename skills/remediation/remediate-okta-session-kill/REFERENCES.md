# References — remediate-okta-session-kill

## Okta API

- **Okta Users API — Sessions** — https://developer.okta.com/docs/reference/api/users/#user-sessions
  - `DELETE /api/v1/users/{userId}/sessions` — revoke all active sessions
  - Returns 204 No Content on success; 404 if the user does not exist
- **Okta Users API — OAuth tokens** — https://developer.okta.com/docs/reference/api/users/#revoke-user-tokens
  - `DELETE /api/v1/users/{userId}/oauth/tokens` — revoke all OAuth refresh tokens for the user across every OAuth client
- **Okta Users API — Lifecycle: Expire Password** — https://developer.okta.com/docs/reference/api/users/#expire-password
  - `POST /api/v1/users/{userId}/lifecycle/expire_password` — force password reset at next login (optional step)

## OCSF wire format

- **OCSF 1.8 Detection Finding (class 2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding — input consumed by this skill

## Threat framework

- **MITRE ATT&CK T1621 Multi-Factor Authentication Request Generation** — https://attack.mitre.org/techniques/T1621/
- **MITRE ATT&CK T1110 Brute Force** — https://attack.mitre.org/techniques/T1110/
- **MITRE ATT&CK T1110.003 Password Spraying** — https://attack.mitre.org/techniques/T1110/003/
- **MITRE ATT&CK Mitigation M1036 Account Use Policies** — https://attack.mitre.org/mitigations/M1036/

## Required Okta API token scope

The API token provided via `OKTA_API_TOKEN_SECRETSMANAGER_ARN` must have the minimum scopes to perform session and token revocation. Per Okta, an admin-level token is required for `/users/{id}/sessions` and `/users/{id}/oauth/tokens` endpoints. The recommended pattern is to provision a dedicated service account with the **Group Admin** role scoped to a containment group, or for stronger least-privilege, a **Custom Role** that grants only:

- `okta.users.sessions.manage`
- `okta.users.tokens.manage`
- `okta.users.lifecycle.manage` (only if password expiration is enabled)

Store the token in AWS Secrets Manager with automatic rotation. The skill fetches it at invocation time; it is never persisted.

## Required AWS IAM (for audit writes)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GetOktaAPIToken",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "${OKTA_API_TOKEN_SECRETSMANAGER_ARN}"
    },
    {
      "Sid": "WriteAuditToDynamoDB",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
      "Resource": "arn:aws:dynamodb:*:*:table/${IAM_AUDIT_DYNAMODB_TABLE}"
    },
    {
      "Sid": "WriteAuditToS3",
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::${IAM_REMEDIATION_BUCKET}/okta-session-kill/audit/*"
    },
    {
      "Sid": "KMSForS3Encryption",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "${KMS_KEY_ARN}",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.${AWS_REGION}.amazonaws.com"
        }
      }
    },
    {
      "Sid": "DenyAllOtherActions_WILDCARD_OK",
      "Effect": "Deny",
      "NotAction": [
        "secretsmanager:GetSecretValue",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "s3:PutObject",
        "kms:GenerateDataKey",
        "kms:Decrypt",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

WILDCARD_OK: the `Deny NotAction Resource: *` is defense in depth — it explicitly refuses every action not on the allow-list, even if a future edit tries to add one.

## Closed-loop verification contract

This skill's apply path writes a `remediation_action` record with `status: applied`. The drift framework (#257) schedules a re-run of the paired detector against the same Okta user within a declared SLA (default 15 minutes). If the re-run produces another finding, the drift framework emits a `remediation_drift` finding. This skill is responsible only for producing the audit trail the verifier consumes.
