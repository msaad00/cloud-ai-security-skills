# GCP Cloud Audit Logs → OCSF 1.8 API Activity (class 6003) field map

Raw GCP Cloud Audit Logs use the `protoPayload` envelope that GCP exports to
Cloud Logging, BigQuery, Pub/Sub, and Cloud Storage. The table below pins the
mapping this skill applies. Claude loads it on demand; the main `SKILL.md`
stays focused on triggers and guardrails.

## Log types handled

- **Admin Activity** — always on, records config changes
- **Data Access** — reads/writes on user-managed resources
- **System Event** — GCP-internal admin actions
- **Policy Denied** — denied by VPC Service Controls or IAM conditions

## protoPayload → OCSF field mapping

| Raw protoPayload field | OCSF 1.8 field | Notes |
|---|---|---|
| `authenticationInfo.principalEmail` | `actor.user.email_addr` | User or service-account email |
| `authenticationInfo.principalSubject` | `actor.user.uid` | Workload-identity subject when present |
| `authenticationInfo.serviceAccountKeyName` | `actor.user.credential_uid` | Identifies the SA key used |
| `authenticationInfo.serviceAccountDelegationInfo[]` | `actor.process.parent.user.name` | Delegation chain root when impersonation occurs |
| `requestMetadata.callerIp` | `src_endpoint.ip` | IPv4 / IPv6 |
| `requestMetadata.callerSuppliedUserAgent` | `http_request.user_agent` | |
| `methodName` | `api.operation` | e.g. `google.iam.admin.v1.CreateServiceAccountKey` |
| `methodName` (verb segment) | `activity_id` | `Create` → 1, `Get`/`List` → 2, `Update`/`Patch` → 3, `Delete` → 4 |
| `serviceName` | `api.service.name` | e.g. `iam.googleapis.com` |
| `resourceName` | `resource.uid` | Fully qualified resource path |
| `response.name` | `resources[].name` | Only copied when it is a sanitized service-account key resource name; full response and `privateKeyData` are not retained |
| `status.code` | `status_id` | 0 → 1 (Success); non-zero → 2 (Failure) |
| `status.message` | `status_detail` | Human-readable error |
| `resource.labels.project_id` | `cloud.account.uid` | |
| `resource.labels.organization_id` | `cloud.org.uid` | Present on org-scoped logs |
| `timestamp` | `time` | RFC 3339 → epoch milliseconds |
| `insertId` | `metadata.uid` | GCP-assigned log dedupe key |

## Output formats

- `--output-format ocsf` — OCSF 1.8 API Activity (6003) JSONL
- `--output-format native` — canonical internal event shape preserving the
  full protoPayload for high-fidelity pipelines

## Activity verb inference

`activity_id` is derived from the last segment of `methodName`:

```
google.iam.admin.v1.CreateServiceAccountKey  →  Create (1)
google.iam.admin.v1.ListServiceAccountKeys   →  Read (2)
google.iam.admin.v1.UpdateServiceAccount     →  Update (3)
google.iam.admin.v1.DeleteServiceAccount     →  Delete (4)
```

Verbs not in the canonical set default to `activity_id: 0` (Other).

## Edge cases and limits

- **Policy Denied** — even if `status.code` is 0, activity is flagged by
  `metadata.original_category: policy_denied` and `status_id: 2`.
- **Data Access logs** — not enabled by default in GCP; the skill doesn't
  require them but emits any that are provided.
- **BigQuery streaming audit logs** have a different shape; not handled here.
- **Cloud Audit Logs for GKE** flow through here; K8s audit logs are handled
  by `ingest-k8s-audit-ocsf` instead.

## Upstream references

- GCP Cloud Audit Logs schema: <https://cloud.google.com/logging/docs/audit>
- protoPayload reference: <https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog>
- OCSF 1.8 API Activity (6003): <https://schema.ocsf.io/1.8.0/classes/api_activity>
