---
name: ingest-security-hub-ocsf
description: >-
  Convert AWS Security Hub findings in ASFF (AWS Security Finding Format) into
  OCSF 1.8 Detection Finding events (class 2004). Validates the required ASFF
  fields, maps the HIGH/MEDIUM/LOW/INFORMATIONAL label (plus the 0-100
  Normalized score) to OCSF severity_id, preserves the aggregated
  Resources[]/Types[]/Compliance context, and extracts MITRE ATT&CK
  annotations from ProductFields when the upstream product emits them.
  Handles single findings, the `{"Findings": [...]}` BatchImport wrapper,
  and EventBridge `Security Hub Findings - Imported` envelopes. Use when the
  user mentions Security Hub ingestion, ASFF normalisation, cross-account
  aggregator pipelines, or unifying findings from multiple AWS security
  services (GuardDuty, Inspector, Macie, Config rules) into OCSF. Do NOT use
  for GuardDuty native findings (use ingest-guardduty-ocsf), CloudTrail audit
  logs (use ingest-cloudtrail-ocsf), or VPC Flow Logs (use
  ingest-vpc-flow-logs-ocsf). Do NOT use as a detection skill — Security Hub
  aggregates detections from upstream products; this skill is a passthrough
  normaliser/validator.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: ocsf
---

# ingest-security-hub-ocsf

Thin passthrough ingestion skill with ASFF validation: raw Security Hub ASFF JSON in → OCSF 1.8 Detection Finding (2004) JSONL out. Security Hub is an aggregator — it already collects findings from GuardDuty, Inspector, Macie, Config, Firewall Manager, and third-party products, all normalised to the same ASFF schema. This skill does one thing: validate that the ASFF required fields are present and transform them into the OCSF wire contract shared by every other skill in `detection-engineering/`.

## Wire contract

Reads any of the three shapes Security Hub emits:

1. **Single finding** — one JSON object per line (NDJSON, e.g. EventBridge → Kinesis Firehose to S3)
2. **BatchImportFindings / GetFindings wrapper** — top-level `{"Findings": [...]}` (the format from `aws securityhub get-findings` or from `BatchImportFindings` request bodies)
3. **EventBridge event envelope** — top-level `{"detail-type": "Security Hub Findings - Imported", "detail": {"findings": [...]}, ...}`; the skill auto-unwraps `detail.findings`.

Writes OCSF 1.8 **Detection Finding** (`class_uid: 2004`, `category_uid: 2`). See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) for the field-level pinning every event matches.

## ASFF validation

The skill enforces the ASFF required fields defined in the AWS Security Hub user guide. A finding is **dropped with a stderr warning** (never fatal) if any of these are missing or empty:

- `SchemaVersion`
- `Id`
- `ProductArn`
- `GeneratorId`
- `AwsAccountId`
- `Types` (must be a non-empty list)
- `CreatedAt`
- `UpdatedAt`
- `Severity` (must be a dict with `Label` or `Normalized`)
- `Title`
- `Description`
- `Resources` (must be a non-empty list)

This keeps the downstream OCSF stream trustable: every record that makes it past the ingester is ASFF-valid *and* OCSF-valid.

## Severity mapping

ASFF carries both a `Label` enum and a 0–100 `Normalized` score. The skill prefers `Label` (more stable), falling back to `Normalized`:

| ASFF `Severity.Label` | Normalized fallback | OCSF `severity_id` |
|---|---:|---:|
| `INFORMATIONAL` | 0 | 1 (Informational) |
| `LOW` | 1–39 | 2 (Low) |
| `MEDIUM` | 40–69 | 3 (Medium) |
| `HIGH` | 70–89 | 4 (High) |
| `CRITICAL` | 90–100 | 5 (Critical) |

The raw label and score are both preserved as observables so rules can pivot either way.

## MITRE ATT&CK extraction

ASFF doesn't have a first-class MITRE field, but several AWS products (GuardDuty, Inspector, Config Conformance Packs) now populate `ProductFields` with `aws/securityhub/annotations/mitre-*` keys or include MITRE hints in the `Types[]` taxonomy. The skill extracts both sources:

1. **Types[] taxonomy walk.** ASFF Types use the format `<namespace>/<category>/<classifier>`. When the namespace is `TTPs` and the category matches a MITRE tactic name, the skill emits a tactic-only attack entry.
2. **ProductFields lookup.** When a key matches `aws/securityhub/annotations/mitre-technique`, the value is parsed for a `T####` technique ID and promoted into `attacks[].technique.uid`.

Findings without any MITRE hints still get a valid OCSF event — `finding_info.attacks[]` is simply empty. Downstream pivots that filter by technique will just skip these, which is the intended behaviour.

## Deterministic finding UID

`finding_info.uid` is derived as `det-shub-<first 8 chars of sha256(ASFF Id)>`. The original ASFF Id (a long ARN) is preserved on `evidence.raw_events[].uid`.

## Compliance passthrough

When the ASFF finding carries a `Compliance` block (typical for Config rules, CIS benchmarks, PCI packs), the skill lifts `Compliance.Status`, `Compliance.StatusReasons[]`, and `Compliance.SecurityControlId` into observables. This lets downstream compliance evaluators (cspm-aws-cis-benchmark, etc.) consume Security Hub findings through the same OCSF pipeline without needing to re-read the raw ASFF.

## Usage

```bash
# Single finding
python src/ingest.py asff.json > asff.ocsf.jsonl

# From a BatchImportFindings request body
aws securityhub get-findings --max-results 100 | python src/ingest.py

# Piped downstream to SARIF
python src/ingest.py asff.json | python ../convert-ocsf-to-sarif/src/convert.py > asff.sarif
```

## Tests

`tests/test_ingest.py` runs the ingester against [`../golden/security_hub_raw_sample.json`](../golden/security_hub_raw_sample.json) and asserts deep-equality against [`../golden/security_hub_sample.ocsf.jsonl`](../golden/security_hub_sample.ocsf.jsonl). Plus unit tests for ASFF validation (every required field), Label vs Normalized severity precedence, Types[] MITRE extraction, ProductFields MITRE extraction, BatchImport wrapper unwrapping, and EventBridge envelope unwrapping.
