# References — iam-departures-remediation

## Standards implemented

- **MITRE ATT&CK** — T1078.004 (Cloud Accounts), T1098.001 (Additional Cloud Credentials), T1531 (Account Access Removal)
  https://attack.mitre.org/techniques/T1078/004/
  https://attack.mitre.org/techniques/T1098/001/
  https://attack.mitre.org/techniques/T1531/
- **NIST CSF 2.0** — PR.AC-1, PR.AC-4, RS.MI-2 — https://www.nist.gov/cyberframework
- **CIS Controls v8** — 5.3, 6.1, 6.2 — https://www.cisecurity.org/controls
- **SOC 2 TSC** — CC6.1, CC6.2, CC6.3, CC7.1

## Cloud APIs

### AWS

- **AWS IAM API** — https://docs.aws.amazon.com/IAM/latest/APIReference/welcome.html
- **AWS STS AssumeRole** — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- **AWS Step Functions ASL** — https://docs.aws.amazon.com/step-functions/latest/dg/concepts-amazon-states-language.html
- **EventBridge S3 Object Created** — https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-s3.html

### Azure Entra

- **Microsoft Graph SDK for Python** — https://learn.microsoft.com/en-us/graph/sdks/sdk-installation
- **Revoke sign-in sessions** — https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions
- **Disable / delete user** — https://learn.microsoft.com/en-us/graph/api/user-update / https://learn.microsoft.com/en-us/graph/api/user-delete

### GCP

- **IAM Service Account API** — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts
- **Workspace Admin SDK** — https://developers.google.com/admin-sdk/directory

### Snowflake

- **DROP USER** — https://docs.snowflake.com/en/sql-reference/sql/drop-user
- **REVOKE OWNERSHIP** — https://docs.snowflake.com/en/sql-reference/sql/revoke-ownership

### Databricks

- **SCIM Users API** — https://docs.databricks.com/api/workspace/users

## HR data sources

- **Snowflake Python connector** — https://docs.snowflake.com/en/developer-guide/python-connector/python-connector
- **Databricks SQL connector** — https://docs.databricks.com/dev-tools/python-sql-connector.html
- **clickhouse-connect** — https://clickhouse.com/docs/integrations/python
- **Workday REST API** — https://community.workday.com/sites/default/files/file-hosting/restapi/

## Required IAM (AWS — central account)

Each Lambda has its own role, scoped to one job. See `infra/cloudformation.yaml` for the canonical policies; the highlights:

- **Parser Lambda** — `s3:GetObject` on `s3://<bucket>/departures/`, `sts:AssumeRole` on the cross-account role (with `aws:PrincipalOrgID` condition), `iam:GetUser` on validation targets, `kms:Decrypt`, CloudWatch Logs.
- **Worker Lambda** — Full IAM remediation actions (`iam:DeleteUser`, `iam:DeleteAccessKey`, etc.) PLUS an explicit `Deny` on `arn:aws:iam::*:user/root`, `arn:aws:iam::*:user/break-glass-*`, `arn:aws:iam::*:user/emergency-*`, and all `:role/*` ARNs. DynamoDB `PutItem`, S3 `PutObject` for audit, KMS encryption.
- **Step Function** — `lambda:InvokeFunction` on the two Lambdas, X-Ray, CloudWatch Logs.
- **EventBridge** — `states:StartExecution` on the Step Function only.
- **DLQ + SNS** — see `infra/cloudformation.yaml`.

## Frameworks the audit row maps to

Each `iam-remediation-audit` DynamoDB row carries enough metadata to feed:

- **OCSF Account Change (3001)** — https://schema.ocsf.io/1.8.0/classes/account_change (a future PR will add a converter that emits OCSF from the audit row so this skill closes the loop with `detection-engineering/`)
- **OCSF Identity & Access Management category (3)** — https://schema.ocsf.io/1.8.0/categories/iam
