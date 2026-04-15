# lateral-movement query pack

Warehouse-native Snowflake implementation of the same detection intent as [`skills/detection/detect-lateral-movement`](../../skills/detection/detect-lateral-movement/SKILL.md).

Use this pack when:
- your lake already stores OCSF-shaped API Activity (`6003`) and Network Activity (`4001`) rows
- you want the correlation to run inside Snowflake with zero egress
- you want OCSF-compatible finding rows without piping data through Python first

Do not use this pack when:
- your table stores raw vendor payloads instead of OCSF-shaped events
- you need the repo-native finding shape instead of OCSF-compatible output
- you need a generalized SQL-pack framework across warehouses; this pack is the first shipped artifact, not a full framework

## Input contract

This SQL expects a pre-existing Snowflake table or view with a single `raw_json VARIANT` column containing one OCSF 1.8 event per row.

Minimum event families:
- API Activity (`class_uid = 6003`) for identity-pivot anchors
- Network Activity (`class_uid = 4001`) for accepted east-west traffic

The pack applies the same core thresholds as the Python detector:
- 15-minute correlation window
- `activity_id = 6` for accepted network traffic only
- `traffic.bytes >= 1024`
- destination IP must be RFC1918 or CGNAT (`100.64.0.0/10`)

## Run

Set the source table, then run the SQL in Snowflake:

```sql
SET source_table = 'SECURITY_EVENTS_OCSF';
SET lookback_hours = 24;
```

Then execute [`snowflake.sql`](./snowflake.sql).

If your column is not named `raw_json`, create a small view that aliases it:

```sql
CREATE OR REPLACE VIEW SECURITY_EVENTS_OCSF AS
SELECT payload AS raw_json
FROM RAW_SECURITY_EVENTS;
```

## Output contract

The query returns one row per deterministic `(provider, session_uid, dst_ip, dst_port)` tuple with:
- stable `finding_uid` / `event_uid`
- ATT&CK `T1021` and `T1078.004`
- `finding_json` as an OCSF-compatible Detection Finding object

The locked output columns and types are listed in:
- [`golden/expected_columns.json`](./golden/expected_columns.json)
- [`golden/expected_column_types.json`](./golden/expected_column_types.json)

## Notes

- This pack keeps the data in Snowflake, but the detection logic stays aligned with the shipped Python skill.
- The SQL is intentionally explicit instead of abstracted through macros so operators can audit it directly.
- This pack is read-only. Persisting the findings is a separate step, for example through `sink-snowflake-jsonl`.
