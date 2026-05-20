---
name: source-clickhouse-query
description: >-
  Run a read-only ClickHouse query and emit the result set as raw JSONL rows
  for downstream ingestion, detection, or view skills. Accepts explicit
  `--query` SQL or reads the query from stdin when no `--query` is provided.
  Only `SELECT`, `WITH`, `SHOW`, and `DESCRIBE` statements are allowed, and
  multiple statements, SQL comments, session controls, optimizer/admin verbs,
  dynamic identifier helpers, and common control/write keywords are rejected.
  Use when the user already has security data in ClickHouse (for example via
  `sink-clickhouse-jsonl`) and wants to pipe lake rows into existing skills
  without exporting files first. Do NOT use for writes, DDL, or admin changes.
  Do NOT use as a detector or normalizer by itself.
purpose: Run a read-only ClickHouse query and emit the result set as raw JSONL rows for downstream ingestion, detection, or view skills.
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: raw
concurrency_safety: stateless
network_egress: "*.clickhouse.cloud"
---

# source-clickhouse-query

Read-only source adapter: ClickHouse query in, raw JSONL rows out. This skill
does not normalize vendor data, detect threats, or write back to ClickHouse.
It is the read-side companion to `sink-clickhouse-jsonl`, completing the
ClickHouse security-data-lake loop: persist findings or events with the sink,
then replay them through any `detect-*`, `view-*`, or `discover-*` skill via
this source.

## Use when

- Security findings or normalized events already live in ClickHouse
- You want to fetch rows directly into a skill pipeline (replay, backfill, recompute)
- You need a read-only source step before `ingest-*`, `detect-*`, `view-*`, or `discover-*`

## Do NOT use

- For `INSERT`, `ALTER`, `DROP`, `CREATE`, `OPTIMIZE`, `TRUNCATE`, `KILL`, or grant operations
- As a detection or remediation skill
- When the source data is not in ClickHouse
- To run arbitrary admin SQL — the read-only normalizer rejects it

## Input

The skill accepts one read-only SQL statement via:

- `--query "SELECT ..."` on the CLI, or
- stdin when `--query` is omitted

Allowed statement families:

- `SELECT`
- `WITH`
- `SHOW`
- `DESCRIBE`

The skill rejects multiple statements, SQL comments, session or optimizer
controls, dynamic identifier helpers, unbalanced query shapes, and
non-read-only verbs.

## Output

Raw JSONL rows exactly as the ClickHouse client returns them, serialized with
JSON-safe string conversion for `DateTime`, `UUID`, `Decimal`, and other
non-JSON-native ClickHouse types.

Typical compositions:

```bash
# Replay yesterday's findings out of the lake into a SARIF view
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "SELECT payload FROM security.findings_sink WHERE ingested_at >= now() - INTERVAL 1 DAY" \
  | jq -c '.payload | fromjson' \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py

# Re-run detection on historical OCSF API Activity rows
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "SELECT payload FROM security.events_sink WHERE schema_mode = 'ocsf' AND ingested_at >= now() - INTERVAL 7 DAY" \
  | jq -c '.payload | fromjson' \
  | python skills/detection/detect-lateral-movement/src/detect.py
```

## Credentials

Uses the standard ClickHouse client environment variables:

- `CLICKHOUSE_HOST`
- `CLICKHOUSE_USER`
- `CLICKHOUSE_PASSWORD`

Optional:

- `CLICKHOUSE_PORT`
- `CLICKHOUSE_DATABASE`
- `CLICKHOUSE_SECURE`

This skill is read-only but still egresses to ClickHouse. Prefer short-lived,
manager-injected credentials and TLS-enabled ClickHouse Cloud endpoints. Pair
the connection with a ClickHouse role granting `SELECT` only on the sink
tables (`security.findings_sink`, `security.events_sink`,
`security.evidence_sink`, `security.audit_sink`) — never `*.*`.
