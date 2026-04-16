# Runtime Profiles

This document gives current-reality sizing guidance for representative skills.

It exists to answer the operator question:

- "What should I size for local CLI, CI, MCP, or a serverless wrapper?"

It does not claim:

- every one of the shipped skills has a unique benchmark profile yet
- remote warehouse latency is captured for write-capable sinks
- these measurements replace operator load testing in a target environment

Read next:

- [DATA_HANDLING.md](DATA_HANDLING.md)
- [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md)
- [ERROR_CODES.md](ERROR_CODES.md)

## Current Repo Reality

The repo does not yet enforce a per-skill `runtime_profile` frontmatter field.

Today, runtime sizing is expressed as:

- representative measurements for three shipped skills
- guidance by skill family
- explicit caveats where external systems dominate runtime

This keeps the sizing story honest while the repo converges on a more granular
per-skill annotation model.

## Measurement Method

These measurements were taken on a local developer workstation on 2026-04-15 by
running the real shipped Python entrypoints against bundled fixtures repeated to
represent larger batches.

Method:

- 3 runs per case
- wall-clock duration from process start to exit
- child-process CPU time from `resource.getrusage(...)`
- peak resident set size from a fresh benchmark parent process
- stdout discarded to avoid terminal rendering cost

Caveats:

- startup overhead matters more on tiny batches than on long-running runners
- MCP, CI, and serverless wrappers add their own invocation overhead around the
  same skill code
- `sink-snowflake-jsonl --apply` depends on warehouse and network latency and is
  not represented by the local dry-run figures below

## Representative Measurements

### ingest-cloudtrail-ocsf

Fixture shape:

- raw CloudTrail JSONL
- repeated to 1,000 and 10,000 input records

| Load level | Input records | Avg wall | Avg CPU user | Avg CPU sys | Peak RSS | Approx throughput |
|---|---:|---:|---:|---:|---:|---:|
| typical | 1,000 | 61.46 ms | 44.07 ms | 11.58 ms | 19.9 MiB | ~16.3k records/s |
| 10x | 10,000 | 235.34 ms | 190.87 ms | 27.75 ms | 39.1 MiB | ~42.5k records/s |

Operator guidance:

- local CLI or CI: 128 MiB is usually enough
- serverless wrappers: start at 256 MiB to keep headroom for wrapper/runtime overhead
- very large raw batches should still be chunked rather than treated as unbounded streams

### detect-lateral-movement

Fixture shape:

- mixed OCSF API Activity and Network Activity rows
- repeated to 1,000 and 10,000 input records

| Load level | Input records | Avg wall | Avg CPU user | Avg CPU sys | Peak RSS | Approx throughput |
|---|---:|---:|---:|---:|---:|---:|
| typical | 1,000 | 59.75 ms | 44.01 ms | 12.43 ms | 25.8 MiB | ~16.7k records/s |
| 10x | 10,000 | 210.15 ms | 171.58 ms | 28.13 ms | 86.8 MiB | ~47.6k records/s |

Operator guidance:

- local CLI or CI: 256 MiB is the safer default
- serverless wrappers: start at 512 MiB if the same worker also handles queue, JSON, or retry overhead
- shard large windows by time or source when the surrounding runtime has hard timeout limits

### sink-snowflake-jsonl

Fixture shape:

- OCSF finding JSONL
- measured in `--dry-run` mode only
- repeated to 500 and 5,000 input records

| Load level | Input records | Avg wall | Avg CPU user | Avg CPU sys | Peak RSS | Approx throughput |
|---|---:|---:|---:|---:|---:|---:|
| typical dry-run | 500 | 61.16 ms | 46.44 ms | 10.25 ms | 18.6 MiB | ~8.2k records/s |
| 10x dry-run | 5,000 | 229.87 ms | 185.87 ms | 19.64 ms | 36.3 MiB | ~21.8k records/s |

Important boundary:

- these numbers measure JSON parse, schema-mode extraction, identifier validation,
  and summary generation
- they do not include remote Snowflake connection setup, warehouse queueing, or
  `executemany(...)` latency in `--apply` mode

Operator guidance:

- dry-run / validation-only paths: 256 MiB is usually enough
- real `--apply` paths: start at 512 MiB and budget primarily for network and warehouse latency
- use bounded input batches rather than treating sinks as infinite streams

## Family-Level Sizing Guidance

Use these as first-pass defaults when a skill has not been benchmarked yet.

| Skill family | First-pass memory | Timeout guidance | Notes |
|---|---:|---:|---|
| `ingest-*` | 128-256 MiB | 30-60 s | mostly parse/normalize/emit work |
| `detect-*` | 256-512 MiB | 30-60 s | correlation-heavy rules need more headroom than simple transforms |
| `discover-*` | 256-512 MiB | 60-300 s | remote API latency often dominates more than CPU |
| `evaluation/*` | 256-512 MiB | 60-300 s | posture/control checks can spend most time waiting on cloud APIs |
| `view/*` | 128-256 MiB | 30-60 s | output-conversion cost is usually modest |
| `source-*` | 256-512 MiB | 60-300 s | dominated by warehouse/object-store fetch latency |
| `sink-*` | 256-512 MiB dry-run, 512 MiB-1 GiB apply | 60-300 s | remote storage latency dominates apply paths |
| `remediation/*` | 512 MiB+ | 300 s+ | approval, audit, and cloud side effects matter more than raw CPU |

## How To Use This Doc

Use this doc to:

- choose a first Lambda / Cloud Function / Container App memory setting
- size a CI job or local integration test runner
- explain to reviewers that the repo is bounded and benchmarked, even when a
  specific skill has not yet been individually profiled

Do not use this doc to:

- assume exact latency in a customer environment
- skip load tests for a high-volume runner or sink deployment
- compare cloud providers or warehouses against each other

## What Comes Next

The next tightening step is a repo-wide `runtime_profile` field in `SKILL.md`
frontmatter so each skill can declare its own intended envelope directly.

Until then, this document is the source of truth for runtime sizing guidance.
