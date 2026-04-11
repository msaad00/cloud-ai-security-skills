# References — ingest-gcp-audit-ocsf

## Source format

- **GCP Cloud Audit Logs overview** — https://cloud.google.com/logging/docs/audit
- **AuditLog protobuf schema** — https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog
- **LogEntry envelope** — https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
- **Audit log types** (Admin Activity / Data Access / System Event / Policy Denied) — https://cloud.google.com/logging/docs/audit#types

## Output format

- **OCSF 1.8 API Activity (class 6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 actor object** — https://schema.ocsf.io/1.8.0/objects/actor

## Required GCP permissions (collection)

To stream audit logs into a place this skill can read (Cloud Storage,
Pub/Sub, BigQuery), the upstream collector needs:

- `roles/logging.viewer` — read log entries
- `roles/logging.privateLogViewer` — for Data Access logs

References:

- https://cloud.google.com/iam/docs/understanding-roles#logging.viewer
- https://cloud.google.com/iam/docs/understanding-roles#logging.privateLogViewer

The skill itself reads from stdin or a local file — no IAM needed.

## gRPC status code → name mapping

The skill decodes `status.code` per gRPC canonical codes:
https://grpc.github.io/grpc/core/md_doc_statuscodes.html

The full mapping table is in `src/ingest.py` (`_GRPC_CODE_NAMES`).

## See also

- `OCSF_CONTRACT.md` (sibling) for the per-skill wire contract
- `ingest-cloudtrail-ocsf` for the AWS equivalent
- `ingest-azure-activity-ocsf` for the Azure equivalent
