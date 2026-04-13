---
name: discover-cloud-control-evidence
description: >-
  Generate deterministic technical-control evidence from raw cross-cloud
  inventory snapshots. Supports AWS, GCP, and Azure inventory inputs and
  produces a machine-readable evidence package for PCI DSS 4.0 and SOC 2
  security reviews without claiming attestation. Use when the user mentions
  PCI evidence, SOC 2 evidence, cloud inventory evidence, audit evidence, or
  wants a reviewable JSON package showing identity surface, externally exposed
  assets, encryption coverage, logging coverage, and key-management coverage
  across cloud environments. Do NOT use as a benchmark evaluator, compliance
  certification tool, or remediation planner. Do NOT use on raw logs or OCSF
  findings.
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+. Read-only. Accepts raw cloud inventory JSON from
  stdin or a file path. Produces deterministic JSON evidence suitable for CLI,
  CI, MCP, and persistent pipelines.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-security
  source: https://github.com/msaad00/cloud-security/tree/main/skills/discovery/discover-cloud-control-evidence
  version: 0.1.0
  frameworks:
    - PCI DSS 4.0
    - SOC 2 TSC
    - NIST AI RMF
    - MITRE ATT&CK
    - MITRE ATLAS
  cloud: multi
  capability: read-only
---

# discover-cloud-control-evidence

Transforms raw AWS, GCP, and Azure inventory snapshots into a technical
evidence package. The goal is to summarize inventory-backed control evidence
for cloud and AI estates without pretending that discovery alone proves
compliance.

## Use when

- You need machine-readable PCI DSS 4.0 or SOC 2 evidence from cloud inventory
- You want to summarize raw AWS, GCP, or Azure inventory into review-ready evidence
- You need stable JSON that highlights identities, public exposure, encryption, logging, and key-management coverage
- You want an evidence package that can be diffed over time or attached to tickets and audit reviews

## Do NOT use

- As a benchmark or control pass/fail engine
- As a replacement for auditor judgement or formal attestation
- On raw logs, OCSF findings, or security alerts
- To infer exploitability or blast radius on its own

## Input contract

The skill accepts one JSON document with any mix of these provider snapshots:

- `aws`
- `gcp`
- `azure`

Each provider section may include relevant inventory such as identities,
storage, logging, encryption, key management, network policies, public IPs,
endpoints, or AI service inventory. The skill only processes the providers and
services present in the supplied input.

## Output contract

The skill emits one deterministic JSON document:

- `artifact_type: technical-control-evidence`
- `frameworks[]` with the requested evidence families
- `inventory_summary` with providers, services, asset counts, and control-surface counts
- `controls[]` with `evidence-ready` / `partial` / `missing` status per control domain
- `gaps[]` only when the source artifact cannot support a given evidence domain

This is evidence, not an attestation.

## Usage

```bash
# Build evidence from a mixed AWS/GCP/Azure inventory snapshot
python src/discover.py inventory.json > cloud-evidence.json

# Limit to PCI-focused evidence
python src/discover.py inventory.json --framework pci --pretty > pci-evidence.json
```

## Security guardrails

- Read-only only. No network calls, no subprocesses, no writes outside the requested output file.
- Secret-like fields are dropped before evidence is generated.
- Unknown or empty source shapes fail closed with a non-zero exit.
- The skill never emits `compliant` / `non-compliant`; it only reports evidence presence and gaps.

## See also

- [`../discover-control-evidence/SKILL.md`](../discover-control-evidence/SKILL.md) — evidence from AI BOM and graph artifacts
- [`../discover-environment/SKILL.md`](../discover-environment/SKILL.md) — graph inventory generation
- [`../discover-ai-bom/SKILL.md`](../discover-ai-bom/SKILL.md) — AI BOM generation
