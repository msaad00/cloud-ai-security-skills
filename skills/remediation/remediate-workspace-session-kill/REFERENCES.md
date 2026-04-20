# References — remediate-workspace-session-kill

## Google Admin SDK

- Directory API — Users.signOut: https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/signOut
- Directory API — Users.update / Users.patch: https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/patch (used to set `changePasswordAtNextLogin: true`)
- Reports API — Activities.list: https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list (used by reverify with `applicationName=login` + `eventName=login_success`)
- Required scopes (passed as the `scopes` arg to the SDK; not links — see Google's [OAuth scope reference](https://developers.google.com/identity/protocols/oauth2/scopes)):
  - `admin.directory.user.security` — signOut + password change
  - `admin.reports.audit.readonly` — reverify

## Google authentication

- Domain-wide delegation guide — https://developers.google.com/identity/protocols/oauth2/service-account
- Service account impersonation pattern — https://cloud.google.com/iam/docs/service-account-impersonation

## MITRE ATT&CK

- T1110 — Brute Force: https://attack.mitre.org/techniques/T1110/ (the password-spraying / repeated-failure pattern)
- T1078 — Valid Accounts: https://attack.mitre.org/techniques/T1078/ (provider-marked suspicious login of a valid identity)
- T1078.004 — Cloud Accounts: https://attack.mitre.org/techniques/T1078/004/ (Workspace-specific subcategory)

## OCSF 1.8

- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding
- The source detector emits class 2004 with `metadata.product.feature.name = "detect-google-workspace-suspicious-login"`; this skill's source-skill check enforces that.

## AWS audit infrastructure (reused from sibling remediation skills)

- DynamoDB `PutItem` — https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
- S3 server-side encryption with KMS — https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
- Audit table partition key is `user_uid`, sort key `action_at` (ISO-8601 UTC). Compatible with the existing audit-table schema used by `remediate-okta-session-kill`.

## Compliance frameworks

- NIST CSF 2.0 — `RS.MI` (Mitigation): contain incidents to prevent expansion of compromise
- SOC 2 — CC6.1 (Logical access controls), CC7.4 (Incident response)
- CIS Google Workspace Benchmark — sections covering session management and login monitoring

## Repo-internal contracts this skill conforms to

- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — `build_verification_record()` + `build_drift_finding()` integrated from day one
- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — 11-principle contract; satisfies all destructive-write principles
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — `human_required` approval model with `min_approvers: 1`
- [`scripts/validate_safe_skill_bar.py`](../../../scripts/validate_safe_skill_bar.py) — enforces dry-run default, deny-list presence

## Related repo code

- [`skills/remediation/remediate-okta-session-kill`](../remediate-okta-session-kill/) — direct shape mirror (same dual-step containment philosophy, different IdP)
- [`skills/ingestion/ingest-google-workspace-login-ocsf`](../../ingestion/ingest-google-workspace-login-ocsf/) — ingestion sibling, shares the same Workspace API surface
