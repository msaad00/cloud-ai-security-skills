# References — remediate-entra-credential-revoke

## Microsoft Graph API

- Service principals overview — https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal
- Update servicePrincipal (the disable call) — https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update
- List keyCredentials / passwordCredentials — https://learn.microsoft.com/en-us/graph/api/resources/keycredential
- List appRoleAssignments — https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto
- List oauth2PermissionGrants — https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-oauth2permissiongrants
- Application permissions reference — https://learn.microsoft.com/en-us/graph/permissions-reference

## Microsoft authentication

- Azure SDK for Python — https://learn.microsoft.com/en-us/python/api/overview/azure
- Service principal authentication via client secret — https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal

## MITRE ATT&CK

- T1098 — Account Manipulation: https://attack.mitre.org/techniques/T1098/
- T1098.001 — Additional Cloud Credentials: https://attack.mitre.org/techniques/T1098/001/ (the credential-addition pattern)
- T1098.003 — Additional Cloud Roles: https://attack.mitre.org/techniques/T1098/003/ (the role-grant-escalation pattern)
- TA0003 — Persistence (parent tactic): https://attack.mitre.org/tactics/TA0003/

## OCSF 1.8

- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding
- Both source detectors emit class 2004 with `metadata.product.feature.name` set to the detector name; this skill's source-skill check enforces that.

## AWS audit infrastructure (reused from sibling remediation skills)

- DynamoDB `PutItem` — https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
- S3 server-side encryption with KMS — https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
- Audit table partition key is `object_id` (the Entra service principal objectId), sort key `action_at` (ISO-8601 UTC).

## Compliance frameworks

- CIS Microsoft Azure Foundations 2.1 — sections covering Entra ID privileged identity management
- NIST CSF 2.0 — `RS.MI` (Mitigation): contain incidents to prevent expansion of compromise
- SOC 2 — CC6.1 (Logical access controls), CC7.4 (Incident response)

## Repo-internal contracts this skill conforms to

- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — `build_verification_record()` + `build_drift_finding()` integrated from day one
- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — 11-principle contract; satisfies all destructive-write principles
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — `human_required` approval model with `min_approvers: 1`
- [`scripts/validate_safe_skill_bar.py`](../../../scripts/validate_safe_skill_bar.py) — enforces dry-run default, deny-list presence

## Related repo code

- [`skills/remediation/iam-departures-aws/src/lambda_worker/clouds/azure_entra.py`](../iam-departures-aws/src/lambda_worker/clouds/azure_entra.py) — sibling Entra code path, but for HR-departure user-deletion (different workflow, different output contract). The Graph SDK setup pattern is the same; consider extracting an `_shared/azure_graph_client.py` helper in a future PR if a third Entra skill ships.
