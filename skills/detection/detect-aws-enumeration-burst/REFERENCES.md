# References — detect-aws-enumeration-burst

- AWS CloudTrail event reference:
  <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html>
- AWS IAM API reference (`GetAccountAuthorizationDetails`, `ListUsers`, `ListRoles`, `ListPolicies`):
  <https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html>
- AWS EC2 API reference (`DescribeInstances`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`):
  <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/OperationList-query-ec2.html>
- AWS Organizations API reference (`DescribeOrganization`, `ListAccounts`):
  <https://docs.aws.amazon.com/organizations/latest/APIReference/Welcome.html>
- MITRE ATT&CK T1526 Cloud Service Discovery:
  <https://attack.mitre.org/techniques/T1526/>
- Upstream ingester: [`ingest-cloudtrail-ocsf`](../../ingestion/ingest-cloudtrail-ocsf/)
