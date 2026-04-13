# References — cspm-aws-cis-benchmark

## Standards implemented

- **CIS AWS Foundations Benchmark v3.0** — https://www.cisecurity.org/benchmark/amazon_web_services
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework
- **ISO/IEC 27001:2022** — https://www.iso.org/standard/27001
- **SOC 2 Trust Services Criteria** — https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
- **PCI DSS 4.0** — https://www.pcisecuritystandards.org/document_library/

## AWS APIs read

| Section | API | Why |
|---|---|---|
| IAM | `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:ListUsers`, `iam:ListAccountAliases`, `iam:GetAccountPasswordPolicy` | Credential hygiene |
| S3 | `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`, `s3:GetBucketLogging` | Storage posture |
| CloudTrail | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors` | Logging coverage |
| EC2 | `ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs` | Network posture |
| KMS | `kms:ListAliases`, `kms:DescribeKey` | Key rotation |

## Required IAM policy

The AWS-managed `SecurityAudit` policy
(https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
covers every API this skill calls. We deliberately use the managed policy
rather than a hand-rolled one so the permission set drifts with AWS's own
security guidance, not ours.

If you want a tighter custom policy, the minimal action set is:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "iam:ListUsers",
      "iam:GetAccountPasswordPolicy",
      "s3:ListAllMyBuckets",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketEncryption",
      "s3:GetBucketVersioning",
      "s3:GetBucketLogging",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs",
      "ec2:DescribeFlowLogs",
      "kms:ListAliases",
      "kms:DescribeKey"
    ],
    "Resource": "*"
  }]
}
```

## SDK

- **boto3** — https://boto3.amazonaws.com/v1/documentation/api/latest/index.html

## Output schema

JSON output is per-finding, with the same `Finding` dataclass shape across all 18 checks. See `src/checks.py` for the canonical definition. SARIF output follows SARIF 2.1.0 — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html.
