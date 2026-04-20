# References — remediate-aws-sg-revoke

## AWS

- RevokeSecurityGroupIngress API — https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupIngress.html
- DescribeSecurityGroups API (used by reverify) — https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html
- IpPermission shape — https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html
- IAM authorization for EC2 SGs — https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html

## MITRE ATT&CK

- T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- M1037 — Filter Network Traffic: https://attack.mitre.org/mitigations/M1037/

## OCSF 1.8

- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding
- Repo-pinned contract: [`skills/detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)

## AWS audit infrastructure

- DynamoDB PutItem — https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
- S3 server-side encryption with KMS — https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
- Audit table partition key is `sg_id`, sort key `action_at` (ISO-8601 UTC)

## Compliance frameworks

- NIST CSF 2.0 — `RS.MI` (Mitigation), `PR.AC-05` (Network integrity)
- SOC 2 — CC6.6 (Logical and physical access controls)
- CIS AWS Foundations 2.x — sections 5.2 / 5.3 (no SG allows ingress from 0.0.0.0/0 on admin or database ports)

## Repo-internal contracts this skill conforms to

- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — `build_verification_record()` + `build_drift_finding()` integrated from day one
- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — 11-principle contract; satisfies all destructive-write principles
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — `human_required` approval model with `min_approvers: 1`
- [`scripts/validate_safe_skill_bar.py`](../../../scripts/validate_safe_skill_bar.py) — enforces dry-run default, deny-list presence

## Related repo skills

- [`detect-aws-open-security-group`](../../detection/detect-aws-open-security-group/) — paired source detector
- [`cspm-aws-cis-benchmark`](../../evaluation/cspm-aws-cis-benchmark/) — periodic posture equivalent (read-only); the streaming detector + this remediator close the loop in near-real-time
- [`iam-departures-aws`](../iam-departures-aws/) — sibling AWS write skill; shares the dual-audit pattern
