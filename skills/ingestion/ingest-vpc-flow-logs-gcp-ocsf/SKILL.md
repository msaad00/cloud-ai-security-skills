---
name: ingest-vpc-flow-logs-gcp-ocsf
description: >-
  Convert raw GCP VPC Flow Logs records into OCSF 1.8 Network Activity
  (class 4001). Accepts Cloud Logging LogEntry envelopes or bare
  jsonPayload-shaped records, maps connection metadata, byte counters,
  VPC and instance context, and normalizes accepted or denied traffic into
  a deterministic OCSF stream. Use when the user has GCP VPC Flow Logs and
  wants OCSF-normalized network telemetry for correlation, detection, or
  rendering. Do NOT use on firewall rule logs, packet mirroring, or raw
  pcap. Do NOT use when the source is AWS or Azure network telemetry.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
---

# ingest-vpc-flow-logs-gcp-ocsf

## Use when

- You have GCP VPC Flow Logs from Cloud Logging exports
- You need OCSF Network Activity for downstream detection or storage
- You want a parity path alongside AWS VPC Flow Logs and Azure NSG Flow Logs

## Do NOT use

- On non-GCP network telemetry
- On raw pcap or packet mirroring captures
- As a detection skill; this only normalizes telemetry

## Input

JSONL or a top-level JSON array of GCP VPC Flow Logs entries. Supports both:

- full Cloud Logging `LogEntry` envelopes with `jsonPayload`
- bare `jsonPayload`-style objects containing `connection`, `src_*`, `dest_*`, and counter fields

## Output

OCSF 1.8 Network Activity (class `4001`) JSONL with:

- `src_endpoint` / `dst_endpoint`
- `traffic.bytes` and `traffic.packets`
- `connection_info.protocol_*`, `direction`, and `boundary`
- `cloud.provider = GCP`
- `cloud.account.uid` from the project

## Notes

- `disposition` maps to OCSF activity IDs where present; when absent, records default to accepted traffic
- byte and packet counters are aggregated across both directions when both are present
- timestamps preserve flow `start_time` / `end_time` when the source provides them
