# Error Codes

This file defines the repo-wide exit-code contract for CLI skills, wrappers,
validators, and related tooling.

The main goal is simple:

- `stdout` stays for structured results
- `stderr` carries warnings, partial-skip information, and human-debug detail
- exit codes signal whether the invocation succeeded, failed, or should be
  treated as a contract-breaking condition

Read next:

- [SKILL_CONTRACT.md](SKILL_CONTRACT.md)
- [DEBUGGING.md](DEBUGGING.md)
- [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)

## Current Repo Reality

Today, the repo is already consistent on the two most important codes:

- `0` means success
- `1` means fatal failure

That is the only cross-repo exit-code behavior that operators should assume is
universally implemented today.

Also true today:

- many ingest and detect skills skip malformed records with a warning on
  `stderr` and still exit `0`
- several evaluation skills use `1` to signal that high- or critical-severity
  findings were present, even when the skill itself ran correctly
- write-capable skills typically return `1` for failed apply paths

This doc standardizes the intended meanings so future work can converge on a
single operator contract without pretending every existing skill already uses
all codes below.

## Exit Code Meanings

| Code | Meaning | Operator interpretation |
|---|---|---|
| `0` | success | the skill completed its intended work; inspect `stdout` for results and `stderr` for warnings |
| `1` | fatal failure | the invocation did not complete its contract; treat results as unusable unless the skill explicitly documents otherwise |
| `2` | invalid input or contract violation | reserved repo meaning for bad CLI args, unsupported input shape, or declared contract mismatch |
| `3` | auth, permission, or approval failure | reserved repo meaning for denied cloud access, missing approval context, or rejected write precondition |
| `4` | environment or dependency failure | reserved repo meaning for missing SDK, broken local environment, or required external binary unavailable |
| `5` | upstream source or network failure | reserved repo meaning for API outage, sink unavailability, or read/write transport failure |
| `6` | partial or degraded success | reserved repo meaning for skills that intentionally support partial completion as part of their contract |

## Rules

### 1. `0` means the skill contract succeeded

`0` does not mean "nothing unusual happened."

It means:

- the invocation completed successfully enough for its structured output to be
  trusted
- any partial-skip or warning behavior was handled inside the documented
  contract

Examples:

- an ingester skips one malformed record, emits a warning on `stderr`, and
  still emits valid normalized events
- a detector processes the batch successfully but finds no matching behavior

### 2. `1` means the invocation failed

Use `1` when the skill cannot safely uphold its contract.

Examples:

- the input file cannot be opened
- the required cloud call fails and no valid result can be produced
- a sink apply path fails to write and cannot produce a trustworthy success
  summary
- a validator detects contract violations

### 3. Reserved codes are meanings, not promises of universal implementation

Codes `2-6` are the repo's intended meanings. They are not yet guaranteed to be
implemented across every shipped skill.

That distinction matters:

- operators can design toward these semantics now
- maintainers can converge on them without a hidden breaking change
- docs stay honest about current behavior

## Partial And Degraded Results

The repo supports two different patterns. They must not be confused.

### Pattern A: success with skipped records

This is common today for ingestion and detection skills.

Meaning:

- a few records were malformed, unsupported, or intentionally skipped
- the overall invocation still produced valid output
- exit code stays `0`
- `stderr` must make the skip behavior visible

### Pattern B: explicit partial success

This is reserved for skills that intentionally document partial completion as a
first-class outcome.

Meaning:

- the skill completed only part of its intended work
- the partial nature of the result matters to the operator
- exit code `6` is the intended repo-wide meaning once adopted by a skill that
  explicitly documents it

Until a skill declares that behavior in its contract, operators should not
assume `6` is in use.

## `stderr` Expectations

Use `stderr` for:

- malformed-record warnings
- skipped-event reasons
- environment or dependency errors
- permission or approval failures
- machine-readable telemetry when `SKILL_LOG_FORMAT=json` or
  `AGENT_TELEMETRY=1` is enabled

Do not use `stderr` for:

- the primary result payload
- secret or token values
- silently swallowing a failure that should have been a non-zero exit

## Guidance By Skill Family

| Family | Expected current behavior |
|---|---|
| `ingest-*` | `0` on successful normalization, even with documented skipped-line warnings; `1` on fatal parse/input/runtime failure |
| `detect-*` | `0` on successful analysis, even when no finding is produced; `1` on fatal failure |
| `evaluation/*` | `0` when checks pass their configured threshold; some current skills use `1` when critical/high checks fail |
| `view/*` | `0` on successful conversion; `1` on fatal input or conversion failure |
| `discover-*` | `0` on successful inventory/evidence generation; some skills may encode partial status in the payload rather than the exit code |
| `sink-*` | `0` on dry-run or successful write path; `1` on failed write or failed environment precondition |
| `remediation/*` | `0` on successful dry-run or approved execution; non-zero on approval, environment, or execution failure |
| `scripts/validate_*` | `0` on pass; `1` on validation failure |

## MCP And CI Interpretation

### MCP

The MCP wrapper should treat:

- `0` as successful tool execution
- non-zero as tool failure unless the wrapped skill explicitly documents a
  different contract

The wrapper must not reinterpret a failing skill as success because `stderr`
looked non-fatal.

### CI

CI should treat non-zero as step failure unless the workflow intentionally marks
the step advisory.

That is already how the repo's main validation lanes behave.

## Migration Guidance

When tightening an existing skill:

1. keep `0` and `1` stable unless there is a strong reason to change
2. document any use of reserved codes in `SKILL.md` and tests
3. add tests for the error path, not just the happy path
4. prefer explicit `stderr` warnings over silent record drops
5. update this doc if a reserved code becomes broadly adopted

## Audit Summary Of Current State

As of this doc:

- `0` and `1` are the only repo-wide reliable exit-code contract
- partial-skip behavior is mostly surfaced on `stderr`, not in distinct exit
  codes
- `2-6` are standardized meanings for convergence work, not universal runtime
  guarantees yet

That is intentional: the contract is now written down without overstating the
tree's current uniformity.
