---
name: ingest-snowflake-query-history-ocsf
description: >-
  Convert Snowflake ACCOUNT_USAGE.QUERY_HISTORY rows into OCSF 1.8 API Activity
  (6003) or native records. Parses QUERY_TEXT per statement to derive a canonical
  api.operation and an unmapped.snowflake.* block for the shipped Snowflake
  detectors: privileged role grants, RSA key-pair additions, network-policy
  disable, session-policy widening, replication / failover to external accounts,
  share creation and account additions, warehouse resize bursts, and bulk data
  egress (COPY INTO location / GET). It preserves the Snowflake QUERY_ID for
  SIEM-friendly dedupe and correlation. Use when the user mentions Snowflake
  QUERY_HISTORY ingestion, Snowflake audit / query-log normalization, feeding
  Snowflake control-plane activity into an OCSF pipeline, or driving the
  detect-snowflake-* rules from real query history. Do NOT use for Snowflake
  LOGIN_HISTORY / SESSIONS (login and MFA events), for Databricks or other
  warehouses, or as a detector — this skill only normalizes query-history rows
  into OCSF or native output.
purpose: Convert Snowflake ACCOUNT_USAGE.QUERY_HISTORY rows into OCSF 1.8 API Activity (6003) or native records by parsing QUERY_TEXT into a canonical api.operation and an unmapped.snowflake.* block for the shipped Snowflake detectors.
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
  Requires Python 3.11+. No Snowflake connector required when QUERY_HISTORY rows
  are already exported (e.g. via source-snowflake-query). Read-only — parses
  query-history rows and emits OCSF or native JSONL. Never connects to Snowflake
  and never calls write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-snowflake-query-history-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: snowflake
  capability: read-only
---

# ingest-snowflake-query-history-ocsf

Convert Snowflake `ACCOUNT_USAGE.QUERY_HISTORY` rows into OCSF 1.8 API Activity
(6003) events with deterministic IDs and a per-operation `unmapped.snowflake.*`
block that the `detect-snowflake-*` rules consume.

## Use when

- You have Snowflake `ACCOUNT_USAGE.QUERY_HISTORY` rows (e.g. from `source-snowflake-query`) and need OCSF output
- You want to drive the shipped `detect-snowflake-*` rules from real query history instead of hand-written fixtures
- You need Snowflake control-plane changes (grants, key additions, policy changes, replication, shares, warehouse resizes, unloads) normalized for SIEM, lake, MCP, or downstream detection
- You want a portable event stream that preserves the Snowflake `QUERY_ID` for dedupe and correlation

## Do NOT use

- On Snowflake `LOGIN_HISTORY` or `SESSIONS` rows — login and MFA events are a separate producer (`ingest-snowflake-login-history-ocsf`); QUERY_HISTORY does not record authentication attempts
- On Databricks, BigQuery, Redshift, or other warehouse query logs
- To collect live query history by itself — upstream collection and auth stay outside this skill
- To infer ATT&CK techniques or create findings directly — that is the detector's job

## Input contract

Accepts Snowflake `ACCOUNT_USAGE.QUERY_HISTORY` rows as **NDJSON** (one JSON
object per line) or a **single JSON array**. Column names follow the Snowflake
view (uppercase); lowercase is also accepted for tolerance. Well-known columns:

| Column | Use |
|---|---|
| `QUERY_ID` | `metadata.uid` and `unmapped.snowflake.query_id` |
| `QUERY_TEXT` | parsed to derive `api.operation` + `unmapped.snowflake.*` |
| `QUERY_TYPE` | coarse routing hint (e.g. `UNLOAD` marks an egress) |
| `USER_NAME` | `actor.user.uid` |
| `START_TIME` | `time` (epoch ms; ISO-8601 or epoch accepted) |
| `EXECUTION_STATUS` | `status_id` (`success` → 1, `fail`/`incident` → 2) |
| `BYTES_SCANNED`, `ROWS_UNLOADED` | egress volume signal |
| `WAREHOUSE_NAME` | (via QUERY_TEXT) warehouse resize target |

Optional **enrichment** columns a collector may join in (QUERY_HISTORY itself
does not carry them):

- `CLIENT_IP` — from `ACCOUNT_USAGE.SESSIONS` joined on `SESSION_ID` → `src_endpoint.ip`
- `USER_TYPE` — from `ACCOUNT_USAGE.USERS` (`PERSON` / `SERVICE`) → `actor.user.type`
- `USER_EMAIL` / `LOGIN_NAME` — → `actor.user.name` (defaults to `USER_NAME`)

Rows whose `QUERY_TEXT` is not one of the recognized control-plane statements are
skipped cleanly (never dropped silently): an `ingest_summary` stderr record
reports how many rows were emitted vs skipped.

## Recognized statements → operation

| Statement (parsed from `QUERY_TEXT`) | `api.operation` | Detector |
|---|---|---|
| `GRANT ROLE <r> TO USER/ROLE <g>` | `GRANT_ROLE` | unauthorized-grant |
| `ALTER USER <u> SET RSA_PUBLIC_KEY[_2]=…` | `ALTER_USER` | account-key-creation |
| `ALTER ACCOUNT UNSET NETWORK_POLICY` | `ALTER_ACCOUNT` | network-policy-disable |
| `ALTER NETWORK POLICY <p> SET ALLOWED_IP_LIST=(…)` | `ALTER_NETWORK_POLICY` | network-policy-disable |
| `ALTER DATABASE <db> ENABLE REPLICATION/FAILOVER TO ACCOUNTS …` | `ALTER_DATABASE_ENABLE_REPLICATION` / `…_FAILOVER` | replication-config-change |
| `ALTER/CREATE SESSION POLICY <p> … SESSION_IDLE_TIMEOUT_MINS=…` | `ALTER_SESSION_POLICY` / `CREATE_SESSION_POLICY` | session-policy-bypass |
| `CREATE SHARE <s>` / `ALTER SHARE <s> ADD ACCOUNTS …` | `CREATE_SHARE` / `ALTER_SHARE_ADD_ACCOUNTS` | share-creation |
| `ALTER WAREHOUSE <w> SET WAREHOUSE_SIZE=…` | `ALTER_WAREHOUSE` | warehouse-resize-burst |
| `COPY INTO @stage/uri …` / `GET @stage …` | `COPY_INTO_LOCATION` / `GET` | bulk-data-egress |

`warehouse_size_from` is not present in a single QUERY_HISTORY row (the `SET`
clause carries only the target size). The producer chains it from the previous
resize of the same warehouse seen earlier in the stream, seeding the first
observed resize with Snowflake's `CREATE WAREHOUSE` default of `XSMALL`.

## Output contract

Emits OCSF 1.8 API Activity (6003) JSONL by default; `--output-format native`
selects the repo-owned canonical projection. Every OCSF record carries:

- `class_uid: 6003`, `activity_id: 1`, `type_uid: 600301`
- deterministic `metadata.uid` = Snowflake `QUERY_ID`
- `actor.user.{uid,name,type}`, `api.operation`, `api.service.name`
- `src_endpoint.ip` when a `CLIENT_IP` enrichment is present
- the per-operation `unmapped.snowflake.*` block (always includes `query_id`)

## Usage

```bash
# QUERY_HISTORY export file → OCSF
python src/ingest.py query_history.jsonl > snowflake.ocsf.jsonl

# stream into a detector
python src/ingest.py query_history.jsonl \
  | python ../../detection/detect-snowflake-unauthorized-grant/src/detect.py

# native projection for non-OCSF consumers
python src/ingest.py query_history.jsonl --output-format native > snowflake.native.jsonl
```

## Security guardrails

- Read-only only. No Snowflake connection, no writes, no subprocesses.
- Never concatenates row content into SQL — it only *parses* already-executed
  `QUERY_TEXT`; all rows are treated as untrusted input.
- Keeps the vendor-native `QUERY_ID` for dedupe instead of inventing random IDs.
- Unrecognized statements are skipped and counted on stderr, never guessed.

## See also

- [`../../detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md) — shared OCSF wire contract and version pinning
- [`../source-snowflake-query/SKILL.md`](../source-snowflake-query/SKILL.md) — upstream warehouse query adapter that returns QUERY_HISTORY rows
- [`../../detection/detect-snowflake-unauthorized-grant/SKILL.md`](../../detection/detect-snowflake-unauthorized-grant/SKILL.md) — one of the downstream Snowflake detectors this skill feeds
