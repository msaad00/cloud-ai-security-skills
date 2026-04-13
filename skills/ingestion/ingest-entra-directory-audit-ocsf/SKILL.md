---
name: ingest-entra-directory-audit-ocsf
description: >-
  Convert verified Microsoft Entra directoryAudit events into OCSF 1.8 API
  Activity (6003). The first slice maps Microsoft Graph directory audit events
  for service-principal credential changes, app-role grants, and federated
  identity credential creation into deterministic OCSF records while preserving
  Entra natural IDs such as id, correlationId, and activityDateTime for SIEM
  dedupe and downstream correlation. Use when the user mentions Entra audit log
  ingestion, Microsoft Graph directoryAudit normalization, or feeding Entra
  identity telemetry into an OCSF pipeline. Do NOT use for Okta System Log,
  Azure Activity Logs, or as a detector or policy engine — this skill only
  normalizes verified Microsoft Graph directoryAudit payloads.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
compatibility: >-
  Requires Python 3.11+. No Graph SDK required when directoryAudit payloads are
  already exported. Read-only — validates raw Entra audit shape and emits OCSF
  JSONL only. Never calls write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-entra-directory-audit-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: azure
  capability: read-only
---

# ingest-entra-directory-audit-ocsf

Convert verified Microsoft Entra `directoryAudit` payloads into OCSF 1.8 API
Activity records with deterministic IDs and source-preserving correlation keys.

## Use when

- You have Microsoft Graph `directoryAudit` exports from `/auditLogs/directoryAudits` and need OCSF output
- You want to normalize Entra application, service-principal, and federated-credential audit activity for SIEM, lake, MCP, or downstream detection use
- You need a portable Entra identity event stream that preserves Graph `id`, `correlationId`, `activityDateTime`, and target resource IDs
- You want Graph audit events represented as OCSF API Activity before feeding them into cross-cloud identity detections

## Do NOT use

- On Azure Activity Logs, Okta System Log, Google Workspace audit logs, or CloudTrail
- To collect live Graph data by itself — upstream collection and auth stay outside this skill
- To infer ATT&CK techniques or create findings directly
- To mutate Entra applications, service principals, role assignments, or federated credentials

## Input contract

Accepts one of three raw Microsoft Graph `directoryAudit` shapes:

1. **List API response**

```json
{
  "value": [
    {
      "id": "audit-1",
      "activityDateTime": "2026-04-13T04:00:00Z",
      "activityDisplayName": "Add service principal credentials"
    }
  ]
}
```

2. **Single audit event**

```json
{
  "id": "audit-1",
  "activityDateTime": "2026-04-13T04:00:00Z",
  "activityDisplayName": "Add service principal credentials"
}
```

3. **JSONL stream of audit events**

```json
{"id":"audit-1","activityDateTime":"2026-04-13T04:00:00Z","activityDisplayName":"Add service principal credentials"}
{"id":"audit-2","activityDateTime":"2026-04-13T04:05:00Z","activityDisplayName":"Add app role assignment to service principal"}
```

The first slice intentionally supports a narrow, verified event family:

- `Add service principal credentials`
- `Update application - Certificates and secrets management`
- `Add app role assignment to service principal`
- `Create federated identity credential`

Unsupported `activityDisplayName` values are skipped with a warning to `stderr`.

## Output contract

Emits OCSF 1.8 JSONL as **API Activity (6003)**.

Each output record includes:

- deterministic `metadata.uid` based on Graph `id`, `correlationId`, or a stable hash fallback
- UTC epoch-millisecond `time` from `activityDateTime`
- Graph `correlationId` preserved as `api.request.uid`
- `actor`, `src_endpoint`, and `resources` populated only from verified raw fields
- Entra-specific detail preserved under `unmapped.entra`

## Usage

```bash
# Graph list export
python src/ingest.py entra-directory-audit.json > entra.ocsf.jsonl

# JSONL stream from stdin
cat entra-audit.jsonl | python src/ingest.py > entra.ocsf.jsonl

# explicit output file
python src/ingest.py entra.json --output entra.ocsf.jsonl
```

## Security guardrails

- Read-only only. No Entra or Graph writes. No subprocesses.
- Keeps Graph natural IDs for dedupe and correlation instead of inventing random IDs.
- Uses verified raw fields from official Microsoft Graph docs only; unsupported activities are skipped rather than guessed.
- Normalizes into OCSF only where the class fit is explicit. Unmapped vendor-specific detail stays under `unmapped`.

## See also

- [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — shared OCSF wire contract and version pinning
- [`../ingest-azure-activity-ocsf/SKILL.md`](../ingest-azure-activity-ocsf/SKILL.md) — Azure control-plane audit equivalent
- [`../../detection/detect-lateral-movement/SKILL.md`](../../detection/detect-lateral-movement/SKILL.md) — downstream cross-cloud identity pivot detection
