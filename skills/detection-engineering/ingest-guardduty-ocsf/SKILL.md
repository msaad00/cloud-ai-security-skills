---
name: ingest-guardduty-ocsf
description: >-
  Convert raw AWS GuardDuty findings (native JSON finding format from the
  GuardDuty API, EventBridge, or S3 export) into OCSF 1.8 Detection Finding
  events (class 2004). Extracts MITRE ATT&CK technique and tactic from the
  GuardDuty finding Type string, maps the 1.0-8.9 severity scale to OCSF
  severity_id, preserves Resource context, and emits finding_info.attacks[]
  nested inside finding_info (OCSF 1.8 layout). Use when the user mentions
  GuardDuty ingestion, normalising AWS managed detections into OCSF, feeding
  GuardDuty into a unified finding pipeline, or chaining GuardDuty into the
  convert-ocsf-to-sarif / convert-ocsf-to-mermaid-attack-flow skills. Do NOT
  use for Security Hub ASFF (use ingest-security-hub-ocsf), CloudTrail audit
  logs (use ingest-cloudtrail-ocsf), or VPC Flow Logs (use
  ingest-vpc-flow-logs-ocsf). Do NOT use as a detection skill — GuardDuty IS
  the detector; this skill is a passthrough normaliser.
license: Apache-2.0
---

# ingest-guardduty-ocsf

Thin passthrough ingestion skill: raw GuardDuty finding JSON in → OCSF 1.8 Detection Finding (2004) JSONL out. GuardDuty is already a detection engine — this skill normalises its findings into the same wire format everything else in `detection-engineering/` speaks, so downstream converters (`convert-ocsf-to-sarif`, `convert-ocsf-to-mermaid-attack-flow`) and evaluators consume them uniformly alongside detections from the custom `detect-*` skills.

## Wire contract

Reads any of the three shapes the GuardDuty service emits:

1. **Single finding** — one JSON object per line (NDJSON, e.g. EventBridge → Kinesis Firehose to S3)
2. **API `ListFindings` / `GetFindings` wrapper** — top-level `{"Findings": [...]}` (the format returned by `aws guardduty get-findings`)
3. **EventBridge event envelope** — top-level `{"detail": {...}, "detail-type": "GuardDuty Finding", ...}`; the skill auto-unwraps `detail`.

Writes OCSF 1.8 **Detection Finding** (`class_uid: 2004`, `category_uid: 2`). See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) for the field-level pinning that every event matches.

## GuardDuty Type → MITRE ATT&CK mapping

GuardDuty finding types follow the format:

```
<ThreatPurpose>:<ResourceTypeAffected>/<ThreatFamily>.<DetectionMechanism>[!Artifact]
```

The skill extracts the `ThreatPurpose` prefix and the `ThreatFamily` segment and looks them up in two deterministic tables:

| `ThreatPurpose` | MITRE tactic |
|---|---|
| `Backdoor` | TA0011 Command and Control |
| `CredentialAccess` | TA0006 Credential Access |
| `CryptoCurrency` | TA0040 Impact |
| `DefenseEvasion` / `Stealth` | TA0005 Defense Evasion |
| `Discovery` | TA0007 Discovery |
| `Execution` | TA0002 Execution |
| `Exfiltration` | TA0010 Exfiltration |
| `Impact` | TA0040 Impact |
| `InitialAccess` | TA0001 Initial Access |
| `Persistence` | TA0003 Persistence |
| `Policy` | TA0005 Defense Evasion |
| `PrivilegeEscalation` | TA0004 Privilege Escalation |
| `Recon` | TA0043 Reconnaissance |
| `Trojan` | TA0002 Execution |
| `UnauthorizedAccess` | TA0001 Initial Access |

A secondary exact-match table covers ~20 high-signal GuardDuty finding types with a specific MITRE technique (e.g. `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` → `T1552.005` Cloud Instance Metadata API + `T1078.004` Valid Accounts: Cloud Accounts). When no specific technique is known, the skill emits the tactic-only attack so downstream pivots still work.

## Severity mapping

GuardDuty severity is a float on a 1.0–8.9 scale. The skill maps it to `severity_id`:

| GuardDuty severity | OCSF `severity_id` | Label |
|---:|---:|---|
| 0.0 – 1.9 | 1 | Informational |
| 2.0 – 3.9 | 2 | Low |
| 4.0 – 5.9 | 3 | Medium |
| 6.0 – 7.9 | 4 | High |
| 8.0 – 8.9 | 5 | Critical |

The raw float is also preserved as an observable (`gd.severity`) so rules don't lose precision.

## Deterministic finding UID

`finding_info.uid` is derived as `det-gd-<first 8 chars of sha256(GuardDuty Id)>`, so re-ingesting the same finding always yields the same OCSF uid. The original GuardDuty Id is preserved on `evidence.raw_events[].uid`.

## Usage

```bash
# Single finding
python src/ingest.py guardduty.json > guardduty.ocsf.jsonl

# From EventBridge stream
aws guardduty get-findings --detector-id abc --finding-ids f1 f2 | python src/ingest.py

# Piped downstream
python src/ingest.py gd.json | python ../convert-ocsf-to-sarif/src/convert.py > gd.sarif
```

## What's NOT mapped (yet)

GuardDuty findings carry rich context that OCSF has field homes for; the first version focuses on fields any downstream converter or evaluator needs:

- `finding_info.uid`, `title`, `desc`, `types`
- `finding_info.attacks[]` (tactic + technique + sub_technique when known)
- `finding_info.first_seen_time` / `last_seen_time` (from `Service.EventFirstSeen/LastSeen`)
- `severity_id` (from the 1.0–8.9 scale)
- `cloud.account.uid` / `cloud.region` (from `AccountId` / `Region`)
- `resources[]` (from `Resource.ResourceType` plus the type-specific sub-object)
- A curated `observables[]` list (resource id, resource type, GuardDuty type, severity float)
- `evidence.raw_events[]` with the GuardDuty finding Id + ARN (pointer, not body)

Fields **explicitly out of scope** for v0.1: the full `Service.Action` sub-tree (varies by finding type), `Resource` sub-objects beyond the type tag, NetworkConnectionAction bytes/ports (add when a detector needs them).

## Tests

`tests/test_ingest.py` runs the ingester against [`../golden/guardduty_raw_sample.json`](../golden/guardduty_raw_sample.json) and asserts deep-equality against [`../golden/guardduty_sample.ocsf.jsonl`](../golden/guardduty_sample.ocsf.jsonl). Plus unit tests for the Type → MITRE table, the severity scale, Findings-wrapper unwrapping, and EventBridge detail unwrapping.
