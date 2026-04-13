# References — detect-lateral-movement

## Source formats and schemas

- **AWS CloudTrail user guide** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
- **AWS STS AssumeRole API** — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- **Amazon VPC Flow Logs** — https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
- **GCP Cloud Audit Logs** — https://cloud.google.com/logging/docs/audit
- **GCP IAM Credentials API** — https://cloud.google.com/iam/docs/reference/credentials/rest
- **GCP service account keys** — https://cloud.google.com/iam/docs/keys-create-delete
- **GCP VPC Flow Logs record format** — https://cloud.google.com/vpc/docs/about-flow-logs-records
- **Azure Activity Log schema** — https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema
- **Azure role assignments** — https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments
- **Azure elevate access** — https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin
- **Azure user-assigned managed identities** — https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-manage-user-assigned-managed-identities
- **Azure NSG Flow Logs overview** — https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview
- **OCSF schema** — https://schema.ocsf.io/1.8.0/

## Threat framework

- **MITRE ATT&CK T1021 Remote Services** — https://attack.mitre.org/techniques/T1021/
- **MITRE ATT&CK T1078.004 Cloud Accounts** — https://attack.mitre.org/techniques/T1078/004/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF events from upstream ingest skills.
