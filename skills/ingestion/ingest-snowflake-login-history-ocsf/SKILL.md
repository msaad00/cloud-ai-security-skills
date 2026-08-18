---
name: ingest-snowflake-login-history-ocsf
description: >-
  Convert Snowflake ACCOUNT_USAGE.LOGIN_HISTORY rows into OCSF 1.8 Authentication
  (3002) or native records. Every login attempt — success and failure alike —
  becomes an Authentication event carrying actor.user from USER_NAME,
  src_endpoint.ip from CLIENT_IP, status from IS_SUCCESS, and an
  unmapped.snowflake.{authentication_method,error_code,is_success,...} block
  derived from the FIRST_AUTHENTICATION_FACTOR / SECOND_AUTHENTICATION_FACTOR /
  ERROR_CODE columns. It preserves the Snowflake EVENT_ID for SIEM-friendly dedupe
  and correlation. This is the producer detect-snowflake-failed-mfa-burst consumes
  (failed MFA never produces a QUERY_HISTORY row). Use when the user mentions
  Snowflake LOGIN_HISTORY ingestion, Snowflake login / MFA / authentication log
  normalization, feeding Snowflake login activity into an OCSF pipeline, or driving
  the Snowflake failed-MFA-burst detector from real login history. Do NOT use for
  Snowflake QUERY_HISTORY (control-plane statements are a separate producer,
  ingest-snowflake-query-history-ocsf), for Databricks or other warehouses, or as a
  detector — this skill only normalizes login-history rows into OCSF or native
  output.
purpose: Convert Snowflake ACCOUNT_USAGE.LOGIN_HISTORY rows into OCSF 1.8 Authentication (3002) or native records, mapping IS_SUCCESS / the authentication factors / ERROR_CODE into an unmapped.snowflake.* block for the Snowflake failed-MFA-burst detector.
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
  Requires Python 3.11+. No Snowflake connector required when LOGIN_HISTORY rows
  are already exported (e.g. via source-snowflake-query). Read-only — parses
  login-history rows and emits OCSF or native JSONL. Never connects to Snowflake
  and never calls write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-snowflake-login-history-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: snowflake
  capability: read-only
---

# ingest-snowflake-login-history-ocsf

Convert Snowflake `ACCOUNT_USAGE.LOGIN_HISTORY` rows into OCSF 1.8 Authentication
(3002) events with deterministic IDs and a per-event `unmapped.snowflake.*`
block that the `detect-snowflake-failed-mfa-burst` rule consumes.

## Use when

- You have Snowflake `ACCOUNT_USAGE.LOGIN_HISTORY` rows (e.g. from `source-snowflake-query`) and need OCSF output
- You want to drive `detect-snowflake-failed-mfa-burst` from real login history instead of hand-written fixtures
- You need Snowflake authentication activity (logins, MFA outcomes, failure reasons) normalized for SIEM, lake, MCP, or downstream detection
- You want a portable event stream that preserves the Snowflake `EVENT_ID` for dedupe and correlation

## Do NOT use

- On Snowflake `QUERY_HISTORY` rows — control-plane statements (grants, key adds, policy changes, egress) are a separate producer (`ingest-snowflake-query-history-ocsf`); LOGIN_HISTORY does not record executed statements
- On Databricks, BigQuery, Redshift, or other warehouse login logs
- To collect live login history by itself — upstream collection and auth stay outside this skill
- To infer ATT&CK techniques or create findings directly — that is the detector's job

## Input contract

Accepts Snowflake `ACCOUNT_USAGE.LOGIN_HISTORY` rows as **NDJSON** (one JSON
object per line) or a **single JSON array**. Column names follow the Snowflake
view (uppercase); lowercase is also accepted for tolerance. Well-known columns:

| Column | Use |
|---|---|
| `EVENT_ID` | `metadata.uid` and `unmapped.snowflake.event_id` |
| `EVENT_TIMESTAMP` | `time` (epoch ms; ISO-8601 or epoch accepted) |
| `EVENT_TYPE` | `unmapped.snowflake.event_type` |
| `USER_NAME` | `actor.user.uid` |
| `CLIENT_IP` | `src_endpoint.ip` |
| `REPORTED_CLIENT_TYPE` | `unmapped.snowflake.reported_client_type` |
| `FIRST_AUTHENTICATION_FACTOR` | factor context; fallback `authentication_method` |
| `SECOND_AUTHENTICATION_FACTOR` | the MFA factor → primary `authentication_method` |
| `IS_SUCCESS` | `status_id` (`YES` → 1, `NO` → 2) + `unmapped.snowflake.is_success` |
| `ERROR_CODE` | `unmapped.snowflake.error_code` |
| `ERROR_MESSAGE` | `unmapped.snowflake.error_message` |

Optional **enrichment** columns a collector may join in from
`ACCOUNT_USAGE.USERS` on `USER_NAME` (LOGIN_HISTORY itself does not carry them):

- `USER_TYPE` — (`PERSON` / `SERVICE`) → `actor.user.type`
- `USER_EMAIL` / `LOGIN_NAME` — → `actor.user.name` / `actor.user.email_addr` (defaults to `USER_NAME`)

Every LOGIN_HISTORY row is an authentication attempt, so every row with an
attributable `USER_NAME` is emitted (success and failure alike). Rows without a
`USER_NAME` are skipped cleanly (never dropped silently): an `ingest_summary`
stderr record reports how many rows were emitted vs skipped.

## Authentication-method mapping

`unmapped.snowflake.authentication_method` prefers `SECOND_AUTHENTICATION_FACTOR`
(the MFA factor) and falls back to `FIRST_AUTHENTICATION_FACTOR`.
`detect-snowflake-failed-mfa-burst` matches MFA markers (`MFA`, `DUO`, `TOTP`,
`WEBAUTHN`, `PASSCODE`, `PUSH`, …) in that value, together with
`is_success = false`, to aggregate failed-MFA bursts per principal.

## Output contract

Emits OCSF 1.8 Authentication (3002) JSONL by default; `--output-format native`
selects the repo-owned canonical projection. Every OCSF record carries:

- `class_uid: 3002`, `activity_id: 1` (Logon), `type_uid: 300201`
- `status_id: 1` on success, `2` on failure (LOGIN_HISTORY records login attempts; OCSF activity is always Logon, status distinguishes the outcome)
- deterministic `metadata.uid` = Snowflake `EVENT_ID`
- `actor.user.{uid,name,type}`, `src_endpoint.ip` when a `CLIENT_IP` is present
- the per-event `unmapped.snowflake.*` block (always includes `authentication_method`, `is_success`, `error_code`, `event_id`)

## Usage

```bash
# LOGIN_HISTORY export file → OCSF
python src/ingest.py login_history.jsonl > snowflake_login.ocsf.jsonl

# stream into the failed-MFA-burst detector
python src/ingest.py login_history.jsonl \
  | python ../../detection/detect-snowflake-failed-mfa-burst/src/detect.py

# native projection for non-OCSF consumers
python src/ingest.py login_history.jsonl --output-format native > snowflake_login.native.jsonl
```

## Security guardrails

- Read-only only. No Snowflake connection, no writes, no subprocesses.
- Treats every row as untrusted input; never concatenates row content into SQL.
- Keeps the vendor-native `EVENT_ID` for dedupe instead of inventing random IDs.
- Unattributable rows (no `USER_NAME`) are skipped and counted on stderr, never guessed.

## See also

- [`../../detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md) — shared OCSF wire contract and version pinning
- [`../ingest-snowflake-query-history-ocsf/SKILL.md`](../ingest-snowflake-query-history-ocsf/SKILL.md) — sibling producer for Snowflake control-plane statements
- [`../source-snowflake-query/SKILL.md`](../source-snowflake-query/SKILL.md) — upstream warehouse query adapter that returns LOGIN_HISTORY rows
- [`../../detection/detect-snowflake-failed-mfa-burst/SKILL.md`](../../detection/detect-snowflake-failed-mfa-burst/SKILL.md) — the downstream detector this skill feeds
