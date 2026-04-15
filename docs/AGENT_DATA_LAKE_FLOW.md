# Agent Data Lake Flow

This repo supports three practical lake/runtime cases. Use the narrowest path that matches the data you already have.

## 1. Raw vendor data

`raw vendor data -> source-* | ingest-* | detect-*`

Use this when the lake holds original vendor payloads. The flow is:

1. `source-*` adapters read the vendor data.
2. `ingest-*` skills normalize it with deterministic reference transforms.
3. `detect-*` skills evaluate the normalized result.

Source adapters are read-only. They do not mutate the lake.

## 2. OCSF or repo-native lake data

`OCSF / repo-native lake data -> source-* | detect-*`

Use this when the lake already contains OCSF, canonical, or other repo-native records. In this case:

1. `source-*` adapters read the stored lake shape.
2. `detect-*` skills consume it directly.

No ingest step is required if the lake record is already in the detection-ready shape.

## 3. Custom schema lake data

`custom schema lake data -> agent-written SQL projection -> detect-*`

Use this when the lake schema is customer-specific and does not match the repo contract. The agent writes a SQL projection that maps the custom tables into the fields expected by `detect-*`.

Keep the projection small and explicit:

- select only the columns needed for detection
- preserve stable identifiers and timestamps
- avoid introducing write-back or schema changes

## Operator rule

Prefer read-only source access, deterministic ingest transforms, and the smallest projection that gets the data into `detect-*`.
