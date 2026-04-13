# References — detect-lateral-movement-aws

## Source formats and schemas

- **AWS CloudTrail user guide** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
- **Amazon VPC Flow Logs** — https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
- **OCSF schema** — https://schema.ocsf.io/1.8.0/

## Threat framework

- **MITRE ATT&CK T1021 Remote Services** — https://attack.mitre.org/techniques/T1021/
- **MITRE ATT&CK T1078.004 Cloud Accounts** — https://attack.mitre.org/techniques/T1078/004/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF events from upstream ingest skills.
