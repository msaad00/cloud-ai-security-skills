---
name: ingest-nsg-flow-logs-azure-ocsf
description: >-
  Convert Azure NSG Flow Logs tuples into OCSF 1.8 Network Activity
  (class 4001). Parses the nested Azure Network Watcher flow-log export
  structure, supports tuple versions 1 and 2, normalizes allow or deny
  decisions, and preserves subscription and boundary context. Use when the
  user has Azure NSG Flow Logs and wants OCSF-normalized network telemetry
  for correlation, detection, or storage. Do NOT use on Azure Activity
  Logs or Defender alerts. Do NOT use on AWS or GCP flow-log formats.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
---

# ingest-nsg-flow-logs-azure-ocsf

## Use when

- You have Azure NSG Flow Logs from Network Watcher exports
- You need OCSF Network Activity output
- You want parity with AWS VPC Flow Logs and GCP VPC Flow Logs ingestors

## Do NOT use

- On Azure Activity Log events
- On Defender for Cloud alerts
- As a detector or remediation skill

## Input

JSON or JSONL of Azure NSG Flow Logs export payloads. The skill walks:

- `records[]` / `Records[]`
- `properties.flows[]`
- nested `flows[]`
- `flowTuples[]`

## Output

OCSF 1.8 Network Activity (class `4001`) JSONL with:

- source and destination IP/port
- packet and byte counters where tuple version provides them
- `cloud.provider = Azure`
- subscription and NSG boundary context
