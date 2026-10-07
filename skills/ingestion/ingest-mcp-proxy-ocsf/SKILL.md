---
name: ingest-mcp-proxy-ocsf
description: >-
  Convert raw MCP proxy logs (from agent-bom proxy or any MCP JSON-RPC middleware)
  into Application Activity records. OCSF 1.8 (class 6002) is the default output,
  with a native projection available via `--output-format native`. Every event carries
  session_uid, JSON-RPC method, direction, and
  a stable tool fingerprint (sha256 of name + description + inputSchema + annotations)
  so downstream detection skills can spot schema drift. Use when the user mentions
  MCP proxy logs, OCSF ingestion, detection engineering pipeline, or wants to feed
  MCP traffic into a SIEM or detection stack. Do NOT use for CloudTrail, GCP audit,
  Azure Activity, or K8s audit logs (use ingest-cloudtrail-ocsf / ingest-gcp-audit-ocsf
  / ingest-azure-activity-ocsf / ingest-k8s-audit-ocsf respectively). Do NOT use as a
  detection skill — this skill only normalises, it does not flag anything.
purpose: Convert raw MCP proxy logs (from agent-bom proxy or any MCP JSON-RPC middleware) into Application Activity records.
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
---

# ingest-mcp-proxy-ocsf

Thin, single-purpose ingestion skill: raw MCP proxy JSONL in → OCSF 1.8 Application Activity JSONL by default, or the repo-owned native application-activity projection when requested. No detection logic, no side effects, no external calls.

## Wire contract

Reads the format emitted by the `agent-bom proxy` command:

```json
{
  "timestamp":  "2026-04-10T05:00:00.000Z",
  "session_id": "sess-abc",
  "method":     "tools/list",
  "direction":  "response",
  "body":       { "tools": [ ... ] }
}
```

Writes OCSF 1.8 Application Activity (class 6002) with the `cloud_security_mcp` custom profile. See [`../../detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md) for the field-level pinning.

## Usage

```bash
# Single file, OCSF default
python src/ingest.py mcp-proxy.jsonl > mcp-proxy.ocsf.jsonl

# Native projection
python src/ingest.py mcp-proxy.jsonl --output-format native > mcp-proxy.native.jsonl

# Piped from a running proxy
agent-bom proxy "<server cmd>" --log-format jsonl \
  | python src/ingest.py \
  | python ../../detection/detect-mcp-tool-drift/src/detect.py \
  > findings.ocsf.jsonl
```

## Native output format

When `--output-format native` is selected, the skill emits the repo-owned
canonical projection instead of the OCSF envelope. Each record includes:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "application_activity"`
- `event_uid`
- `provider`
- `time_ms`
- `session_uid`
- `method`
- `direction`
- `tool` when the source event declares a tool

Example:

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "application_activity",
  "event_uid": "7a1c...",
  "provider": "MCP",
  "time_ms": 1775797200000,
  "session_uid": "sess-abc",
  "method": "tools/list",
  "direction": "response",
  "tool": {
    "name": "query_db",
    "fingerprint": "sha256:..."
  }
}
```

## Opt-in content preservation

By default the OCSF output keeps **no** MCP content: tool `inputSchema` is
reduced to `mcp.tool.input_schema_sha256`, and sampling prompts, message text,
and `tools/call` arguments are dropped. Two content detectors cannot fire on
that output:
[`detect-mcp-plugin-supply-chain`](../../detection/detect-mcp-plugin-supply-chain/)
and [`detect-mcp-adversarial-input-corpus`](../../detection/detect-mcp-adversarial-input-corpus/).

`--preserve-mcp-content` (or `MCP_PRESERVE_CONTENT=1`) opts in to keeping
exactly the fields those detectors read, in both OCSF and native output:

| Raw field | Output field | Notes |
|---|---|---|
| `body.tools[].inputSchema` (`tools/list` response) | `mcp.tool.input_schema` | omitted with `mcp.tool.input_schema_omitted: "size_cap"` when its compact JSON exceeds the cap |
| `params.systemPrompt` (e.g. `sampling/createMessage`) | `unmapped.mcp.prompt` | truncated to the cap |
| `params.messages[].content` | `unmapped.mcp.request.params.messages[].content` | text blocks only, joined with `\n`; image/audio data is never kept; truncated to the cap |

- Per-field cap: `MCP_PRESERVE_CONTENT_MAX_CHARS` characters (default 16384).
  Truncated fields are listed in `unmapped.mcp.truncated_fields`.
- The flag never adds `tools/call` arguments to OCSF output.
- Native output (`--output-format native`) already carries the raw `params`
  and `body` objects verbatim, independent of this flag; treat native output
  as raw proxy content for retention purposes.
- When on, a single `mcp_content_preserved` stderr event records the decision.
- Fingerprints, event UIDs, and every other field are identical with or
  without the flag; with the flag off, output is byte-identical to earlier
  releases.

Privacy: preserved prompts and schemas can contain user data, secrets, or
attacker-controlled text. Turn the flag on only where the downstream sink is
approved for that content. Truncation means an injection placed past the cap,
or a schema padded past the cap, is not scanned — treat
`truncated_fields` / `input_schema_omitted` as a signal in their own right.
See [`docs/DATA_HANDLING.md`](../../../docs/DATA_HANDLING.md#mcp-content-preservation).

```bash
python src/ingest.py --preserve-mcp-content mcp-proxy.jsonl \
  | python ../../detection/detect-mcp-adversarial-input-corpus/src/detect.py
```

## Fingerprint

For every `tools/list` response entry and every `tools/call` request, the skill emits an OCSF event with a stable `mcp.tool.fingerprint`:

```python
fingerprint = sha256(
    json.dumps(
        {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "inputSchema": tool.get("inputSchema", {}),
            "annotations": tool.get("annotations", {}),
        },
        sort_keys=True,
    ).encode()
).hexdigest()
```

This is the pivot point for detection skills. Anything that makes the fingerprint change = tool drift.

## Behaviour on malformed input

- One bad line → warning to stderr, skipped, pipeline continues.
- Missing or unparseable `timestamp` → line skipped with a `timestamp_unparseable` stderr warning (never stamped with the current time).
- Missing `session_id` → `"sess-unknown"` (detected by downstream detection skills).
- Empty file → zero output lines, exit 0.

## Tests

`tests/test_ingest.py` runs the skill against [`../../detection-engineering/golden/mcp_proxy_raw_sample.jsonl`](../../detection-engineering/golden/mcp_proxy_raw_sample.jsonl) and asserts the output matches [`../../detection-engineering/golden/mcp_proxy_sample.ocsf.jsonl`](../../detection-engineering/golden/mcp_proxy_sample.ocsf.jsonl) with volatile fields scrubbed.
