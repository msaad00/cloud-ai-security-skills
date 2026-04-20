# References — detect-aws-open-security-group

## AWS

- AuthorizeSecurityGroupIngress API — https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html
- IpPermission shape — https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html
- CloudTrail event reference — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html

## MITRE ATT&CK

- T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- TA0001 — Initial Access: https://attack.mitre.org/tactics/TA0001/

## OCSF

- API Activity (class 6003): https://schema.ocsf.io/1.8.0/classes/api_activity (input shape)
- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding (output shape)
- Repo-pinned contract: [`skills/detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)

## Compliance

- CIS AWS Foundations 2.x — sections 5.2 / 5.3 (ensure no SG allows ingress from 0.0.0.0/0 on admin or database ports)
- NIST CSF 2.0 — `PR.AC-05` (Network integrity is protected)

## Related repo skills

- [`ingest-cloudtrail-ocsf`](../../ingestion/ingest-cloudtrail-ocsf/) — upstream
- [`remediate-aws-sg-revoke`](../../remediation/remediate-aws-sg-revoke/) — paired closed-loop remediator
- [`cspm-aws-cis-benchmark`](../../evaluation/cspm-aws-cis-benchmark/) — periodic posture equivalent
