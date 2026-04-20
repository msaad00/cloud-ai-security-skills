# References — remediate-azure-nsg-revoke

## Azure

- Network Security Group security rules — https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
- `azure-mgmt-network` SDK reference (`SecurityRulesOperations`) — https://learn.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.networkmanagementclient
- `SecurityRulesOperations.begin_delete` — https://learn.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.v2023_09_01.operations.securityrulesoperations
- `SecurityRulesOperations.begin_create_or_update` — https://learn.microsoft.com/en-us/python/api/azure-mgmt-network/azure.mgmt.network.v2023_09_01.operations.securityrulesoperations
- `azure-identity` `DefaultAzureCredential` — https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential
- Azure built-in role `Network Contributor` (delete + write) — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/networking
- Azure built-in role `Reader` (reverify) — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general

## MITRE ATT&CK

- T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- M1037 — Filter Network Traffic: https://attack.mitre.org/mitigations/M1037/

## OCSF 1.8

- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding
- Repo-pinned contract: [`skills/detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)

## Audit infrastructure (shared with sibling AWS / GCP remediators)

- DynamoDB PutItem — https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
- S3 server-side encryption with KMS — https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
- Audit table partition key is `rule_id` (Azure ARM id), sort key `action_at` (ISO-8601 UTC)

## Compliance frameworks

- NIST CSF 2.0 — `RS.MI` (Mitigation), `PR.AC-05` (Network integrity)
- SOC 2 — CC6.6 (Logical and physical access controls)
- CIS Azure Foundations 2.x — section 6 (Networking; no NSG allows ingress from `Internet` / `*` / `0.0.0.0/0` / `::/0` on admin or database ports)

## Repo-internal contracts this skill conforms to

- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — `build_verification_record()` + `build_drift_finding()` integrated from day one
- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — 11-principle contract; satisfies all destructive-write principles
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — `human_required` approval model with `min_approvers: 1`
- [`scripts/validate_safe_skill_bar.py`](../../../scripts/validate_safe_skill_bar.py) — enforces dry-run default, deny-list presence

## Related repo skills

- [`detect-azure-open-nsg`](../../detection/detect-azure-open-nsg/) — paired source detector
- [`remediate-aws-sg-revoke`](../remediate-aws-sg-revoke/) — AWS sibling
- [`cspm-azure-cis-benchmark`](../../evaluation/cspm-azure-cis-benchmark/) — periodic posture equivalent (read-only); the streaming detector + this remediator close the loop in near-real-time
- [`remediate-entra-credential-revoke`](../remediate-entra-credential-revoke/) — Azure identity-side sibling; shares the dual-audit pattern
