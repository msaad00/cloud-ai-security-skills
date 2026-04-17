# privilege-escalation-k8s query pack

Warehouse-native Snowflake implementation of the same detection intent as [`skills/detection/detect-privilege-escalation-k8s`](../../skills/detection/detect-privilege-escalation-k8s/SKILL.md).

Use this pack when:
- your lake already stores OCSF-shaped Kubernetes API Activity (`6003`) rows
- you want Kubernetes privilege-escalation detection to run inside Snowflake with zero egress
- you want OCSF-compatible finding rows without piping audit data through Python first

Do not use this pack when:
- your table stores raw kube-apiserver audit payloads instead of OCSF-shaped events
- you need the repo-native finding shape instead of OCSF-compatible output
- you need generalized warehouse macros; this pack is an explicit, auditable Snowflake artifact

## Input contract

The shipped SQL files expect a pre-existing table or view containing one OCSF 1.8 event per row:

- `snowflake.sql`: `raw_json VARIANT`
- `databricks.sql`: `raw_json STRING`

Minimum event family:
- API Activity (`class_uid = 6003`) for normalized Kubernetes audit events

The pack implements the same four rule families as the Python detector:
- service-account secret enumeration + read (`T1552.007`)
- service-account pod exec (`T1611`)
- non-admin RBAC self-grant (`T1098`)
- service-account token self-grant (`T1550.001`)

The same Rule 1 correlation window is used:
- `300` seconds / 5 minutes

## Run

Set the source table, then run the SQL in your warehouse:

```sql
SET source_table = 'K8S_AUDIT_OCSF';
SET lookback_hours = 24;
```

Then execute one of:

- [`snowflake.sql`](./snowflake.sql)
- [`databricks.sql`](./databricks.sql)

If your column is not named `raw_json`, create a small view that aliases it:

```sql
CREATE OR REPLACE VIEW K8S_AUDIT_OCSF AS
SELECT payload AS raw_json
FROM RAW_K8S_AUDIT;
```

## Output contract

The query returns one row per deterministic finding with:
- stable `finding_uid` / `event_uid`
- `rule_name`
- ATT&CK `T1552.007`, `T1611`, `T1098`, or `T1550.001`
- `finding_json` as an OCSF-compatible Detection Finding object

The locked output columns and types are listed in:
- [`golden/expected_columns.json`](./golden/expected_columns.json)
- [`golden/expected_column_types.json`](./golden/expected_column_types.json)
- [`golden/expected_column_types_databricks.json`](./golden/expected_column_types_databricks.json) for Databricks

## Notes

- This pack keeps the data in the warehouse, but the detection logic stays aligned with the shipped Python skill.
- The SQL is intentionally explicit so operators can audit each rule directly.
- This pack is read-only. Persisting findings is a separate step, for example through `sink-snowflake-jsonl`.
