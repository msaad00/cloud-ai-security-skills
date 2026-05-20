# Sink Contract

Sinks are the persistence edge of the repo. They are not detectors, not
normalizers, and not remediation workflows. Their job is simple:

`JSONL on stdin -> validated write to a destination -> native sink summary`

## What a sink may do

- read JSONL from `stdin`
- validate destination identifiers and required arguments
- persist records to a pre-provisioned destination
- emit one native `sink_result` object to `stdout`
- support `--dry-run` and explicit apply mode

## What a sink may not do

- create, alter, or drop schema unless the skill contract explicitly says so
- run arbitrary SQL supplied by the caller
- invent detections, evidence, or evaluation logic
- hide writes behind a default “apply” mode

## Required skill frontmatter

Every shipped sink must declare:

- `capability: write-sink`
- `approval_model: human_required`
- `side_effects: writes-database` or `writes-storage`
- `input_formats`
- `output_formats: native`
- `execution_modes` including `persistent` if it is safe to run in a loop

## Required CLI behavior

Every sink must provide:

- `--dry-run` as the default posture
- an explicit apply flag
- identifier validation before any network call
- non-zero exit on write failure
- stderr messaging for operator warnings and failure detail

## Output contract

Every sink writes one repo-native summary object to `stdout` with at least:

- `schema_mode: "native"`
- `record_type: "sink_result"`
- destination identity such as `table`, `bucket`, or `object_key`
- `dry_run`
- input record count
- written or would-write counts

## Write-safety requirements

### Snowflake / database-style sinks

- pre-provisioned table only
- parameterized inserts only
- validated identifier path only
- explicit transaction control where the client supports it

### Object-store sinks

- validated bucket and prefix
- one-way writes to new objects unless overwrite is a documented contract
- no object mutation disguised as append

## Audit and approval expectations

Sink skills are write-capable, so they must remain operator-reviewable:

- caller role and approver role frontmatter
- documented blast radius in `Do NOT use`
- MCP exposure should mark the tool as destructive

## Current shipped sinks

- `sink-snowflake-jsonl`
- `sink-clickhouse-jsonl` — paired with the read-side
  `source-clickhouse-query` skill and the
  [`packs/clickhouse/`](../packs/clickhouse/) DDL pack (findings / events /
  evidence / audit tables, materialized views, row-level policies) for the
  end-to-end [security data lake hero use case](CLICKHOUSE_DATA_LAKE.md)
- `sink-s3-jsonl`

These are the current reference implementations for future sink work.
