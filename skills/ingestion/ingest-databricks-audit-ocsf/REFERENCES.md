# References — ingest-databricks-audit-ocsf

## Source schema (Databricks audit logs)

- **Audit log reference (record structure)** — https://docs.databricks.com/aws/en/admin/account-settings/audit-logs
- **Audit log system table (`system.access.audit`)** — https://docs.databricks.com/aws/en/admin/system-tables/audit-logs
- **Configure audit log delivery** — https://docs.databricks.com/aws/en/admin/account-settings/audit-log-delivery

The audit record carries `serviceName`, `actionName`, `requestParams`,
`response` (`statusCode`, `errorMessage`, `result`), `userIdentity` (`email`),
`workspaceId`, `sourceIPAddress`, `requestId`, and `timestamp` in the
workspace audit-log delivery (camelCase); the `system.access.audit` system
table exposes the same fields in snake_case (`service_name`, `action_name`,
`request_params`, `status_code`, `user_identity`, `workspace_id`,
`source_ip_address`, `request_id`). `requestParams` values are strings; nested
structures (e.g. `init_scripts`) are stringified JSON. This producer accepts
either casing and parses stringified JSON defensively.

## Mapped services / actions (official audit action names)

- **Clusters events** (`clusters.create`, `clusters.edit`; `init_scripts`, `cluster_name`, `cluster_id`) — https://docs.databricks.com/aws/en/admin/account-settings/audit-log-reference
- **MLflow Model Registry events** (`getModelVersionDownloadUri`, `transitionModelVersionStage`) — https://docs.databricks.com/aws/en/mlflow/model-registry
- **Secrets events** (`getSecret`; `scope`, `key`) — https://docs.databricks.com/aws/en/security/secrets/
- **Token management events** (`generateDbToken`; `lifetime_seconds`, `comment`) — https://docs.databricks.com/aws/en/admin/access-control/tokens
- **Unity Catalog / Delta Sharing events** (`createRecipient`, `createShare`; `authentication_type`) — https://docs.databricks.com/aws/en/data-sharing/
- **Account / workspace admin events** (`setAdmin`, `addUserToGroup`; `targetUserName`, `group_name`) — https://docs.databricks.com/aws/en/admin/users-groups/

The downstream `detect-databricks-*` rules anchor on canonical operation
strings that do not always equal a naive `serviceName.actionName` join — the
Unity Catalog Delta-Sharing verbs are anchored in PascalCase
(`unityCatalog.CreateRecipient`) and PAT issuance is anchored as
`tokens/create`. The producer's operation registry maps each vendor-native
`(serviceName, actionName)` pair to the exact canonical string the detector
consumes, and documents the mapping in `src/ingest.py::OPERATION_REGISTRY`.

## Output format

- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 Actor object** — https://schema.ocsf.io/1.8.0/objects/actor
- **OCSF 1.8 schema browser** — https://schema.ocsf.io/

## Collection guidance

The skill itself reads JSON from stdin or local files and never connects to
Databricks. Upstream collectors should:

- deliver workspace audit logs to object storage, or query
  `system.access.audit` with parameterised queries (never string-concatenate)
- preserve `serviceName`, `actionName`, `requestParams`, `response`,
  `userIdentity`, `workspaceId`, `sourceIPAddress`, `requestId`, `timestamp`

Databricks notes that audit-log delivery and the `system.access.audit` system
table have ingestion latency. The skill keeps the source `timestamp` and
`requestId` intact so downstream correlation can reason about ordering and
dedupe explicitly.
