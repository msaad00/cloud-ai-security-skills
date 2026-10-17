---
name: detect-mcp-unbounded-tool-output
description: >-
  Detect MCP tools whose response payloads systematically exceed operator-set
  output ceilings — the OWASP LLM10:2025 Unbounded Consumption pattern
  applied to the tool-output side of the loop. Reads OCSF 1.8 Application
  Activity (class 6002) records produced by ingest-mcp-proxy-ocsf and tracks
  per-(session_uid, tool_name) cumulative breaches where
  unmapped.mcp.response_size_bytes crosses MCP_TOOL_OUTPUT_BYTES_THRESHOLD
  (default 10 MiB) OR unmapped.mcp.response_line_count crosses
  MCP_TOOL_OUTPUT_LINES_THRESHOLD (default 50000). Fires one Detection
  Finding when MCP_TOOL_OUTPUT_REPEATED_BREACH_THRESHOLD (default 5) breaches
  accumulate in the same session for the same tool. Use when the user
  mentions tool-output exhaustion, MCP RLIMITs, unbounded LLM consumption,
  or OWASP LLM10. Do NOT use on raw MCP proxy logs — feed them through
  ingest-mcp-proxy-ocsf first. Do NOT use as a per-call rate limiter; this
  is a cumulative pattern detector that complements wrapper RLIMITs.
purpose: Detect MCP tools repeatedly pushing past output ceilings (OWASP LLM10:2025 Unbounded Consumption).
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: canonical, native, ocsf
output_formats: native, ocsf
concurrency_safety: stateless
---

# detect-mcp-unbounded-tool-output

## Attack pattern

A tool exposed via MCP can leak operator budget and overwhelm the agent's
context window by returning oversized payloads on every call. A single
oversized payload is a bug; a tool that *systematically* breaches the
operator's per-call ceiling across a single session is a footgun — either a
mis-configured tool or an adversary intentionally bleeding the operator
through cost or context bloat.

This maps to OWASP LLM Top 10 **LLM10:2025 Unbounded Consumption**.

## Detection logic

Walk MCP Application Activity events from `ingest-mcp-proxy-ocsf`. For each
event carrying `unmapped.mcp.response_size_bytes` or
`unmapped.mcp.response_line_count`, check whether either crosses its
threshold:

- `MCP_TOOL_OUTPUT_BYTES_THRESHOLD` — default `10485760` (10 MiB)
- `MCP_TOOL_OUTPUT_LINES_THRESHOLD` — default `50000`

Count cumulative breaches per `(session_uid, tool_name)`. When the count
reaches `MCP_TOOL_OUTPUT_REPEATED_BREACH_THRESHOLD` (default `5`), fire one
Detection Finding. Severity `MEDIUM` — chronic, not acute.

```
state[(session_uid, tool_name)] = breach_count
fire when breach_count >= MCP_TOOL_OUTPUT_REPEATED_BREACH_THRESHOLD
```

- Same `(session, tool)` keeps breaching → one finding only (the first
  crossing). Re-running on the same input is idempotent.
- Different tool, same session → counted separately.
- Different session, same tool → counted separately (cross-session
  policy is an MCP server tuning question, not a detection target here).

Use when the user mentions OWASP LLM10, tool-output flooding, MCP RLIMIT
tuning, or unbounded consumption. Do NOT use as a per-call rate limiter.

## Output contract

One OCSF 1.8 Detection Finding (class 2004) per `(session, tool)` that
crosses the breach count. With `--output-format native` the skill emits
the repo-owned native projection.

OCSF output populates:

- `finding_info.types[] = ["mcp-unbounded-tool-output", "llm-unbounded-consumption"]`
- `finding_info.attacks = []` — no adversary-technique attribution from
  resource thresholds alone.
- deterministic `finding_info.uid`.
- `observables[]` — session uid, tool name, breach count, threshold values.

## Evidence limits

Threshold crossings preserve observed counts and operator limits. They do not
establish malicious intent, billing impact, or service unavailability. Native
`mitre_attacks` and OCSF `finding_info.attacks` are empty; an empty mapping list
does not mean there is no finding. Finding IDs, severity, thresholds, and
observed evidence remain stable.

MITRE ATLAS Cost Harvesting (`AML.T0034`) is related investigation context,
not an emitted mapping: the rule does not determine whether consumption was
deliberately driven to cause financial harm. The OWASP reference is pinned to
LLM10:2025; LLM04 from the earlier edition is not a second current mapping.
See [REFERENCES.md](REFERENCES.md) for the source definitions.

## Usage

```bash
python ../../ingestion/ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python src/detect.py \
  > unbounded-output-findings.ocsf.jsonl

# Tighten thresholds in a controlled environment
MCP_TOOL_OUTPUT_BYTES_THRESHOLD=1048576 \
MCP_TOOL_OUTPUT_REPEATED_BREACH_THRESHOLD=3 \
  python src/detect.py mcp-proxy.ocsf.jsonl
```
