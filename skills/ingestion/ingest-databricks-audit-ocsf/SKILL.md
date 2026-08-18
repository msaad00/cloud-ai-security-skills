---
name: ingest-databricks-audit-ocsf
description: >-
  Convert Databricks audit-log records into OCSF 1.8 API Activity (6003) or
  native records. Resolves each (serviceName, actionName) pair through an
  explicit operation registry to derive a canonical api.operation and an
  unmapped.databricks.* block for the shipped Databricks detectors: cluster
  init-script abuse, MLflow model-artifact exfiltration, secret-scope read
  bursts, personal-access-token creation, Unity Catalog cross-workspace /
  external Delta Sharing, and workspace/account admin grants. It preserves the
  Databricks requestId for SIEM-friendly dedupe and correlation. Use when the
  user mentions Databricks audit-log ingestion, system.access.audit
  normalization, feeding Databricks control-plane activity into an OCSF
  pipeline, or driving the detect-databricks-* rules from real audit records.
  Do NOT use for Databricks SQL query history, for Snowflake or other
  warehouses, or as a detector — this skill only normalizes audit records into
  OCSF or native output.
purpose: Convert Databricks audit-log records into OCSF 1.8 API Activity (6003) or native records by resolving each (serviceName, actionName) pair into a canonical api.operation and an unmapped.databricks.* block for the shipped Databricks detectors.
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. No Databricks connector required when audit records are
  already exported (workspace audit-log delivery or the system.access.audit
  system table). Read-only — parses audit records and emits OCSF or native
  JSONL. Never connects to Databricks and never calls write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-databricks-audit-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: databricks
  capability: read-only
---

# ingest-databricks-audit-ocsf

Convert Databricks audit-log records into OCSF 1.8 API Activity (6003) events
with deterministic IDs and a per-operation `unmapped.databricks.*` block that
the `detect-databricks-*` rules consume.

## Use when

- You have Databricks audit records (workspace audit-log delivery, or the
  `system.access.audit` system table) and need OCSF output
- You want to drive the shipped `detect-databricks-*` rules from real audit
  activity instead of hand-written fixtures
- You need Databricks control-plane changes (cluster edits, MLflow model
  downloads, secret reads, PAT issuance, Delta Sharing, admin grants)
  normalized for SIEM, lake, MCP, or downstream detection
- You want a portable event stream that preserves the Databricks `requestId`
  for dedupe and correlation

## Do NOT use

- On Databricks SQL query history / statement logs — those are a separate
  concern and are not audit records
- On Snowflake, BigQuery, Redshift, or other warehouse logs
- To collect live audit records by itself — upstream collection and auth stay
  outside this skill
- To infer ATT&CK techniques or create findings directly — that is the
  detector's job

## Input contract

Accepts Databricks audit records as **NDJSON** (one JSON object per line) or a
**single JSON array**. Both the camelCase workspace audit-log delivery shape
and the snake_case `system.access.audit` system-table shape are accepted.
Well-known fields:

| Field (either casing) | Use |
|---|---|
| `requestId` / `request_id` | `metadata.uid` |
| `serviceName` + `actionName` | resolved to `api.operation` + block builder |
| `requestParams` / `request_params` | parsed to the `unmapped.databricks.*` block |
| `response.statusCode` / `.status_code` | `status_id` (`<400` → 1, else 2) |
| `response.result` | secondary source for ids returned by the API (cluster_id, token_id) |
| `userIdentity.email` / `user_identity.email` | `actor.user.{uid,name,email_addr}` |
| `workspaceId` / `workspace_id` | `unmapped.databricks.workspace_id` |
| `timestamp` | `time` (epoch ms; ISO-8601 or epoch accepted) |
| `sourceIPAddress` / `source_ip_address` | `src_endpoint.ip` |

Databricks encodes `requestParams` values as strings (nested structures such as
`init_scripts` arrive as stringified JSON). The producer parses those
defensively. Records whose `(serviceName, actionName)` pair is not in the
operation registry are skipped cleanly (never dropped silently): an
`ingest_summary` stderr record reports how many records were emitted vs skipped.

## Recognized actions → operation

The vendor-native `(serviceName, actionName)` pair is resolved to the canonical
`api.operation` string that the downstream detector anchors on. The downstream
anchors use PascalCase for the Unity Catalog Delta-Sharing verbs and a
`tokens/create` spelling for PAT issuance, so the registry normalizes to that
contract rather than a naive `service.action` join.

| Databricks `serviceName.actionName` | `api.operation` | `api.service.name` | Detector |
|---|---|---|---|
| `clusters.create` / `clusters.edit` | `clusters.create` / `clusters.edit` | `databricks.clusters` | cluster-init-script-abuse |
| `mlflowModelRegistry.getModelVersionDownloadUri` | `mlflow.getModelVersionDownloadUri` | `databricks.mlflow` | mlflow-model-exfil |
| `mlflowModelRegistry.transitionModelVersionStage` | `mlflow.transitionModelVersionStage` | `databricks.mlflow` | mlflow-model-exfil |
| `secrets.getSecret` | `secrets.getSecret` | `databricks.secrets` | secret-scope-read-burst |
| `accounts.generateDbToken` | `tokens/create` | `databricks.token-management` | token-creation |
| `unityCatalog.createRecipient` / `updateRecipient` | `unityCatalog.CreateRecipient` / `UpdateRecipient` | `databricks.unity-catalog` | unity-catalog-cross-workspace-share |
| `unityCatalog.createShare` / `updateShare` | `unityCatalog.CreateShare` / `UpdateShare` | `databricks.unity-catalog` | unity-catalog-cross-workspace-share |
| `accounts.setAdmin` | `accounts.setAdmin` | `databricks.iam` | workspace-admin-grant |
| `accounts.addUserToGroup` | `iam.addUserToGroup` | `databricks.iam` | workspace-admin-grant |

Delta Sharing recipient `type` is derived from `requestParams.authentication_type`
(`TOKEN` → `EXTERNAL`, `DATABRICKS` → `DATABRICKS`).

## Output contract

Emits OCSF 1.8 API Activity (6003) JSONL by default; `--output-format native`
selects the repo-owned canonical projection. Every OCSF record carries:

- `class_uid: 6003`, `activity_id: 1`, `type_uid: 600301`
- deterministic `metadata.uid` = Databricks `requestId`
- `actor.user.{uid,name,email_addr,type}`, `api.operation`, `api.service.name`
- `src_endpoint.ip` when `sourceIPAddress` is present
- the per-operation `unmapped.databricks.*` block (always includes `workspace_id`)

## Usage

```bash
# audit-log export file → OCSF
python src/ingest.py databricks_audit.jsonl > databricks.ocsf.jsonl

# stream into a detector
python src/ingest.py databricks_audit.jsonl \
  | python ../../detection/detect-databricks-token-creation/src/detect.py

# native projection for non-OCSF consumers
python src/ingest.py databricks_audit.jsonl --output-format native > databricks.native.jsonl
```

## Security guardrails

- Read-only only. No Databricks connection, no writes, no subprocesses.
- Treats every audit record as untrusted input; only *parses* already-recorded
  `requestParams` — never re-executes or concatenates them into any call.
- Keeps the vendor-native `requestId` for dedupe instead of inventing random IDs.
- Unrecognized `(serviceName, actionName)` pairs are skipped and counted on
  stderr, never guessed.

## See also

- [`../../detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md) — shared OCSF wire contract and version pinning
- [`../source-databricks-query/SKILL.md`](../source-databricks-query/SKILL.md) — read-only Databricks warehouse query adapter
- [`../../detection/detect-databricks-token-creation/SKILL.md`](../../detection/detect-databricks-token-creation/SKILL.md) — one of the downstream Databricks detectors this skill feeds
