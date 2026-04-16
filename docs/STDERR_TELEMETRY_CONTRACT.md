# Stderr Telemetry Contract

This document defines the repo-local structured `stderr` contract used by
`skills/_shared/runtime_telemetry.py`.

Use this doc when you need to:

- understand the exact wire shape of skill diagnostics on `stderr`
- parse machine-readable warnings or skip hints from a skill that opts into
  structured telemetry
- keep wrappers, tests, and downstream tooling aligned on the same event shape

Read next:

- [ERROR_CODES.md](ERROR_CODES.md)
- [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md)
- [DEBUGGING.md](DEBUGGING.md)
- [schemas/stderr-telemetry.schema.json](schemas/stderr-telemetry.schema.json)

## Scope

This contract applies to repo-owned skills and wrappers that call
`emit_stderr_event(...)`.

It does not:

- change stdout payloads
- define external telemetry shipping
- replace skill-specific error handling or exit-code behavior
- permit secrets, tokens, or raw credentials in diagnostics

## Activation

The shared helper emits one of two `stderr` forms:

- plain text by default
- JSONL when `SKILL_LOG_FORMAT=json` or `AGENT_TELEMETRY=1`

In both modes the helper writes one line per event and flushes immediately.
It never writes diagnostic data to stdout.

## Plain Text Form

When JSON mode is disabled, the helper emits a human-readable single line:

`[skill-name] message`

This mode is for operator readability and quick local debugging.

## JSONL Form

When JSON mode is enabled, each `stderr` line is a single JSON object with:

- `timestamp`
- `skill`
- `level`
- `event`
- `message`
- any additional fields passed by the caller, excluding `None`

The helper sorts object keys before serializing them.

### Field Semantics

- `timestamp` is UTC ISO-8601 with millisecond precision and a trailing `Z`
- `skill` is the stable skill name passed by the caller
- `level` is a caller-supplied severity string such as `warning` or `error`
- `event` is a machine-friendly identifier such as `json_parse_failed`
- `message` is the human-readable explanation for operators
- additional fields should carry compact machine data such as `line`,
  `path`, `count`, or `error`

## Contract Rules

- keep messages actionable and safe to print
- prefer structured fields for values that consumers may need to filter on
- omit `None` fields rather than serializing null placeholders
- keep stderr diagnostics short and single-line
- treat stderr telemetry as advisory context, not the primary result payload
- do not include secrets, session tokens, or raw credentials in any field

## Consumer Guidance

- If you enable structured mode, parse `stderr` as JSONL and expect one event
  per line.
- If you do not enable structured mode, treat `stderr` as plain operator text.
- If a skill emits warnings or skip hints, the process may still exit `0`
  when the underlying contract considers the invocation successful.

## Current Implementation

The shared helper lives in
[`skills/_shared/runtime_telemetry.py`](../skills/_shared/runtime_telemetry.py).
It currently recognizes `SKILL_LOG_FORMAT=json` and `AGENT_TELEMETRY=1` as the
JSON switch and falls back to a bracketed plain-text line otherwise.

Future helpers should preserve that backward-compatible behavior so wrappers
and tests can rely on a single stderr contract.

## JSON Schema

The machine-readable schema for JSON mode lives at:

- [schemas/stderr-telemetry.schema.json](schemas/stderr-telemetry.schema.json)

That schema pins:

- the required base fields
- string typing for the shared fields
- open additional properties for skill-specific metadata
