---
name: ingest-mcp-proxy-ocsf
description: >-
  Convert raw MCP proxy logs (from agent-bom proxy or any MCP JSON-RPC middleware)
  into OCSF 1.8 Application Activity events (class 6002) with the cloud_security_mcp
  custom profile. Every event carries session_uid, JSON-RPC method, direction, and
  a stable tool fingerprint (sha256 of name + description + inputSchema + annotations)
  so downstream detection skills can spot schema drift. Use when the user mentions
  MCP proxy logs, OCSF ingestion, detection engineering pipeline, or wants to feed
  MCP traffic into a SIEM or detection stack. Do NOT use for CloudTrail, GCP audit,
  Azure Activity, or K8s audit logs (use ingest-cloudtrail-ocsf / ingest-gcp-audit-ocsf
  / ingest-azure-activity-ocsf / ingest-k8s-audit-ocsf respectively). Do NOT use as a
  detection skill — this skill only normalises, it does not flag anything.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
---

# ingest-mcp-proxy-ocsf

Thin, single-purpose ingestion skill: raw MCP proxy JSONL in → OCSF 1.8 Application Activity JSONL out. No detection logic, no side effects, no external calls.

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

Writes OCSF 1.8 Application Activity (class 6002) with the `cloud_security_mcp` custom profile. See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) for the field-level pinning.

## Usage

```bash
# Single file
python src/ingest.py mcp-proxy.jsonl > mcp-proxy.ocsf.jsonl

# Piped from a running proxy
agent-bom proxy "<server cmd>" --log-format jsonl \
  | python src/ingest.py \
  | python ../detect-mcp-tool-drift/src/detect.py \
  > findings.ocsf.jsonl
```

## Fingerprint

For every `tools/list` response entry and every `tools/call` request, the skill emits an OCSF event with a stable `mcp.tool.fingerprint`:

```python
fingerprint = sha256(json.dumps({
    "name":        tool["name"],
    "description": tool.get("description", ""),
    "inputSchema": tool.get("inputSchema", {}),
    "annotations": tool.get("annotations", {}),
}, sort_keys=True).encode()).hexdigest()
```

This is the pivot point for detection skills. Anything that makes the fingerprint change = tool drift.

## Behaviour on malformed input

- One bad line → warning to stderr, skipped, pipeline continues.
- Missing `timestamp` → current time.
- Missing `session_id` → `"sess-unknown"` (detected by downstream detection skills).
- Empty file → zero output lines, exit 0.

## Tests

`tests/test_ingest.py` runs the skill against [`../golden/mcp_proxy_raw_sample.jsonl`](../golden/mcp_proxy_raw_sample.jsonl) and asserts the output matches [`../golden/mcp_proxy_sample.ocsf.jsonl`](../golden/mcp_proxy_sample.ocsf.jsonl) with volatile fields scrubbed.
