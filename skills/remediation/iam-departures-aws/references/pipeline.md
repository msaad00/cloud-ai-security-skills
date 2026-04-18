# iam-departures-aws — 13-step deletion pipeline

The skill frontmatter references this file for the full deletion order.
Claude loads it on demand; the `SKILL.md` stays under 1024 chars so it
loads cheaply when trigger phrases fire.

## Ordering contract

IAM objects depend on each other — you cannot delete a user while they are
still attached to groups, owning MFA devices, or holding login profiles.
The 13-step order deletes dependencies first, then the user, so every step
is idempotent against partial prior runs.

| # | Step | API | Notes |
|---|---|---|---|
| 1  | List and revoke all inline user policies | `ListUserPolicies` + `DeleteUserPolicy` | Defense-in-depth; most users have none |
| 2  | Detach all managed user policies | `ListAttachedUserPolicies` + `DetachUserPolicy` | Policy ARNs stay, only the attachment goes |
| 3  | Remove from every group | `ListGroupsForUser` + `RemoveUserFromGroup` | |
| 4  | List access keys and deactivate | `ListAccessKeys` + `UpdateAccessKey Status=Inactive` | Deactivate before delete for audit clarity |
| 5  | Delete all access keys | `DeleteAccessKey` | |
| 6  | List MFA devices and deactivate virtual | `ListMFADevices` + `DeactivateMFADevice` | Virtual MFA is user-owned; hardware is org-owned |
| 7  | Delete virtual MFA devices | `DeleteVirtualMFADevice` | Only ones owned by this user; hardware stays |
| 8  | List SSH public keys and delete | `ListSSHPublicKeys` + `DeleteSSHPublicKey` | CodeCommit-era credential |
| 9  | List signing certificates and delete | `ListSigningCertificates` + `DeleteSigningCertificate` | Legacy SOAP API credential |
| 10 | List service-specific credentials and delete | `ListServiceSpecificCredentials` + `DeleteServiceSpecificCredential` | e.g. CodeCommit HTTPS git creds |
| 11 | Delete login profile (console password) | `DeleteLoginProfile` | |
| 12 | Verify user has zero remaining dependencies | `GetUser` | Fails the whole workflow if anything remains |
| 13 | Delete the user | `DeleteUser` | Final step; writes audit evidence |

## Audit guarantees (per step)

Every step writes two audit rows atomically before returning:

1. **DynamoDB row** keyed by `(iam_username, step_index, remediated_at)` for
   fast lookup by incident responders.
2. **S3 evidence object** at `departures/audit/<username>/<step>/<ts>.json`
   with KMS encryption; object-lock governance mode prevents overwrite.

If either write fails, the step raises and the Step Function retries with
exponential backoff. The Step Function's catch-all writes a DLQ row to SQS
with the partial audit trail so an operator can continue from the exact
failure point.

## Dry-run contract

Every step supports `dry_run=True` which returns the full plan
(`RemediationStatus.DRY_RUN`) with the API calls that would be made, their
arguments, and the expected response shape. Zero AWS API calls are made.
CI runs this mode against every fixture in `tests/fixtures/` to prevent
regressions in step ordering.

## Guardrails enforced in code (not just docs)

- **Grace period**: `--grace-period-days N` default 7; the parser skips any
  termination within that window. Implemented at
  `src/lambda_parser/handler.py::should_remediate()`.
- **Deny list**: hard-coded to reject `root`, `break-glass-*`, `emergency-*`
  before step 1. Also enforced in IAM policy `Deny` statements on the
  `WorkerExecutionRole` and cross-account role.
- **Rehire filter**: 8 scenarios detected by the parser (same email rehired
  before termination effective; new IAM user created post-rehire; etc).
- **Org boundary**: every `sts:AssumeRole` call is scoped by
  `aws:PrincipalOrgID`; the worker cannot escape the AWS Organization.

## Re-verification

After step 13, the next reconciler run MUST find zero AWS IAM users matching
the terminated employee across all target accounts. If it finds one, the
ingest-back to the HR warehouse flags the discrepancy as `closed-loop-failed`
and an operator is paged.

## Upstream references

- IAM user deletion order: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html#id_users_deleting>
- Deleting access keys: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html>
- Step Functions reliability patterns: <https://docs.aws.amazon.com/step-functions/latest/dg/welcome.html>
