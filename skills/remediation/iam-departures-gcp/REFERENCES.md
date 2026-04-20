# References — iam-departures-gcp

Only official `cloud.google.com`, `developers.google.com`, and primary
framework sources. Mirrors the format of `iam-departures-aws/REFERENCES.md`.

## Standards implemented

- **MITRE ATT&CK** — T1078.004, T1098.001, T1531, T1552
  - https://attack.mitre.org/techniques/T1078/004/
  - https://attack.mitre.org/techniques/T1098/001/
  - https://attack.mitre.org/techniques/T1531/
- **NIST CSF 2.0** — PR.AC-1, PR.AC-4, RS.MI-2 — https://www.nist.gov/cyberframework
- **CIS Controls v8** — 5.3, 6.2 — https://www.cisecurity.org/controls
- **CIS GCP Foundations v3** — controls 1.5, 1.7, 1.10 — https://www.cisecurity.org/benchmark/google_cloud_computing_platform
- **SOC 2 TSC** — CC6.1, CC6.2, CC6.3, CC7.1 — https://www.aicpa-cima.com

## GCP APIs

### Identity (Workspace + Cloud Identity)

- **Admin SDK Directory — users.update** — https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/update
- **Admin SDK Directory — users.delete** — https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/delete
- **Admin SDK Directory — tokens.list** — https://developers.google.com/admin-sdk/directory/reference/rest/v1/tokens/list
- **Admin SDK Directory — tokens.delete** — https://developers.google.com/admin-sdk/directory/reference/rest/v1/tokens/delete
- **Admin SDK Reports — activity.list** — https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list
- **Cloud Identity — groups.memberships.list** — https://cloud.google.com/identity/docs/reference/rest/v1/groups.memberships/list
- **Cloud Identity — groups.memberships.delete** — https://cloud.google.com/identity/docs/reference/rest/v1/groups.memberships/delete
- **OAuth 2.0 token revoke** — https://developers.google.com/identity/protocols/oauth2/native-app#tokenrevoke

### IAM and Resource Manager

- **IAM Service Accounts — disable** — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/disable
- **IAM Service Accounts — delete** — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/delete
- **IAM Service Account Keys — list / delete** — https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys
- **IAM Conditions** — https://cloud.google.com/iam/docs/conditions-overview
- **Resource Manager — projects.getIamPolicy** — https://cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy
- **Resource Manager — projects.setIamPolicy** — https://cloud.google.com/resource-manager/reference/rest/v3/projects/setIamPolicy
- **Resource Manager — folders IAM** — https://cloud.google.com/resource-manager/reference/rest/v3/folders/getIamPolicy
- **Resource Manager — organizations IAM** — https://cloud.google.com/resource-manager/reference/rest/v3/organizations/getIamPolicy

### Compute Engine (SSH key cleanup)

- **Compute — projects.setCommonInstanceMetadata** — https://cloud.google.com/compute/docs/reference/rest/v1/projects/setCommonInstanceMetadata
- **Compute — instances.setMetadata** — https://cloud.google.com/compute/docs/reference/rest/v1/instances/setMetadata
- **Managing SSH keys in metadata** — https://cloud.google.com/compute/docs/connect/add-ssh-keys

### BigQuery

- **BigQuery — datasets.get** — https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets/get
- **BigQuery — datasets.patch** — https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets/patch
- **BigQuery — controlling access to datasets** — https://cloud.google.com/bigquery/docs/dataset-access-controls

### Cloud Storage

- **Storage — buckets.getIamPolicy** — https://cloud.google.com/storage/docs/json_api/v1/buckets/getIamPolicy
- **Storage — buckets.setIamPolicy** — https://cloud.google.com/storage/docs/json_api/v1/buckets/setIamPolicy
- **Storage — CMEK encryption** — https://cloud.google.com/storage/docs/encryption/customer-managed-keys

### Serverless control plane

- **Cloud Functions Gen 2 deployment** — https://cloud.google.com/functions/docs/2nd-gen/overview
- **Cloud Workflows — syntax** — https://cloud.google.com/workflows/docs/reference/syntax
- **Eventarc on GCS object.finalized** — https://cloud.google.com/eventarc/docs/cloudstorage
- **Cloud KMS — overview** — https://cloud.google.com/kms/docs
- **Firestore in Native mode** — https://cloud.google.com/firestore/docs/concepts/native-mode
- **Cloud Logging — entries.write** — https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/write
- **Pub/Sub topic + dead-letter** — https://cloud.google.com/pubsub/docs/handling-failures
- **VPC Service Controls** — https://cloud.google.com/vpc-service-controls/docs/overview

## HR data sources (shared with iam-departures-aws)

- **BigQuery Python client** — https://cloud.google.com/bigquery/docs/reference/libraries
- **Snowflake Python connector** — https://docs.snowflake.com/en/developer-guide/python-connector/python-connector
- **Workday REST API** — https://community.workday.com

## Frameworks the audit row maps to

Each Firestore audit row carries enough metadata to feed:

- **OCSF Account Change (3001)** — https://schema.ocsf.io/1.8.0/classes/account_change
- **OCSF Identity & Access Management category (3)** — https://schema.ocsf.io/1.8.0/categories/iam
