---
name: ingest-azure-defender-for-cloud-ocsf
description: >-
  Convert Azure Defender for Cloud alerts into OCSF 1.8 Detection Finding
  (class 2004). Validates the alert envelope, normalizes severity and
  resource context, and emits deterministic passthrough findings suitable
  for downstream enrichment or rendering. Use when the user has Defender
  for Cloud alerts and wants OCSF-normalized findings. Do NOT use on Azure
  Activity Logs, NSG Flow Logs, or custom detections. Do NOT use as a
  detector; Defender already produced the alert and this skill only
  validates and normalizes it.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
---

# ingest-azure-defender-for-cloud-ocsf

## Use when

- You have Defender for Cloud alert payloads from the API or wrappers
- You need OCSF Detection Finding output
- You want parity with GuardDuty, Security Hub, and SCC passthroughs

## Do NOT use

- On Azure Activity Logs
- On NSG Flow Logs
- As a remediation skill

## Input

JSONL or a top-level JSON array of:

- direct Defender alert objects
- REST list wrappers containing `value`

## Output

OCSF 1.8 Detection Findings carrying:

- alert title and description
- Defender severity mapped to OCSF severity_id
- Azure resource and subscription context
- passthrough provenance in `observables[]`
