# Query Packs

`packs/` contains warehouse-native analytics artifacts that run detection intent inside the customer's data platform instead of piping events through Python.

Use a pack when:
- your lake already stores OCSF-shaped rows
- you want the detection to run inside Snowflake with zero egress
- you want OCSF-compatible finding rows that can flow into the same sinks as the Python skills

Do not use a pack when:
- your source data is still raw vendor JSON and needs an `ingest-*` skill first
- you need repo-native output instead of OCSF-compatible findings
- you need a broad multi-warehouse framework; the shipped packs are explicit, auditable SQL artifacts

## Contract

Each pack directory should include:
- `README.md` describing the runtime, input contract, and limits
- one or more warehouse-specific SQL files such as `snowflake.sql`
- `golden/expected_columns.json` locking the output column names
- `golden/expected_column_types.json` locking the output Snowflake types
- integration coverage that proves the SQL keeps the same detection intent as its Python sibling

## Shipped Packs

- `lateral-movement`
- `privilege-escalation-k8s`

## Runtime Selection

- Python skills remain the reference implementation for stdin/stdout pipelines and golden fixtures.
- Query packs are the warehouse-native lane for customers who already store normalized OCSF in their lake.
- Persistence is a separate step, for example through `sink-snowflake-jsonl` or `sink-clickhouse-jsonl`.
