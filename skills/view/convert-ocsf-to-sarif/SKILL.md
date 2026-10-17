---
name: convert-ocsf-to-sarif
description: >-
  Convert OCSF 1.8 Detection Findings (class 2004) into SARIF 2.1.0 results
  for upload to GitHub code scanning. Maps each finding's MITRE ATT&CK
  technique to a SARIF rule (ruleId = technique.uid), maps severity_id to
  SARIF level (CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note),
  and projects observables[] into SARIF locations and properties so the
  exported report retains the actor, target resource, and evidence
  pointers. Consumer support for logical locations varies. Use when the user mentions SARIF, GitHub code scanning, GitHub
  Security tab, code scanning upload, or wants detection findings to land
  alongside dependency findings in the same UI. Do NOT use for OCSF events
  that are NOT Detection Findings (class 2004) — Compliance Findings (2003)
  and Inventory Info (5001) need different mappings; a future
  convert-ocsf-compliance-to-sarif will cover those. Do NOT use as a
  detection skill — this only converts.
purpose: Convert OCSF 1.8 Detection Findings (class 2004) into SARIF 2.1.0 results for upload to GitHub code scanning. Maps each finding's MITRE ATT&CK technique to a SARIF rule (ruleId = technique.uid), maps severity_id to SA...
capability: view
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native
concurrency_safety: stateless
---

# convert-ocsf-to-sarif

Cross-vendor view-layer skill: takes OCSF 1.8 Detection Findings (class 2004) on stdin and emits a single SARIF 2.1.0 document on stdout. Used by detection-engineering pipelines that need a portable finding report. The converter creates local output; it does not upload to GitHub or validate how a hosted consumer displays the results.

## Wire contract

Input: JSONL of OCSF Detection Findings produced by any `detect-*` skill in this repo.

Output: A single SARIF 2.1.0 JSON document (one `runs[]` entry, results array containing every input finding). The document validates against [https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json](https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json).

Malformed JSON, non-object records, and non-finding classes fail the entire
conversion with a nonzero exit status. No empty or partial report is emitted,
and an existing `--output` file is preserved on invalid input. Input is fully
consumed before the destination is opened, including when both paths match.
Blank input alone produces a valid empty report; it does not prove coverage.

## Field mapping

| OCSF Detection Finding (2004) field | SARIF 2.1.0 field |
|---|---|
| `finding_info.uid` | `result.properties.finding_uid`; also `result.guid` only when it matches the SARIF GUID pattern |
| `finding_info.title` | `result.message.text` (first line) |
| `finding_info.desc` | `result.message.text` (after the title) |
| `finding_info.attacks[0].technique.uid` | `result.ruleId` |
| `finding_info.attacks[0].technique.name` | `result.rule.shortDescription.text` (under `tool.driver.rules[]`) |
| `finding_info.attacks[0].tactic.uid` + `tactic.name` | `result.rule.properties.tags[]` (e.g. `mitre/attack/initial-access/TA0001`) |
| `finding_info.attacks[0].sub_technique.uid` (if present) | appended to `result.properties.tags[]` |
| `severity_id` | `result.level` per the table below |
| `metadata.product.feature.name` | `result.properties.detector` (which skill emitted the finding) |
| product family | `tool.driver.name` is fixed to `cloud-ai-security-skills-detection-engineering` |
| `time` | `result.properties.detected_at_ms` (ms epoch) |
| `observables[]` | `result.properties.observables[]` (verbatim, so SARIF consumers can pivot) |
| `evidence` | `result.properties.evidence` (verbatim) |
| `finding_info.types[]` | `result.properties.finding_types[]` |

## severity_id → SARIF level

| OCSF severity_id | SARIF level | Reason |
|---:|---|---|
| 0 (Unknown) | `none` | SARIF default |
| 1 (Informational) | `note` | |
| 2 (Low) | `note` | |
| 3 (Medium) | `warning` | |
| 4 (High) | `error` | GitHub Security tab shows as red |
| 5 (Critical) | `error` | |
| 6 (Fatal) | `error` | |

## Identity and consumer boundaries

OCSF finding UIDs are opaque strings. They remain intact in
`result.properties.finding_uid`; the converter never fabricates a UUID from a
name or substitutes a truncated identifier. The existing UID-based
`primaryLocationLineHash` fingerprint remains for compatibility. This is not
proof of global or cross-tenant uniqueness, and duplicate input occurrences
remain separate results in the exported document.

Runtime findings use logical locations derived from detector and UID. The
converter does not invent repository filenames or line numbers. Schema validity
is distinct from successful GitHub ingestion, alert rendering, or deduplication;
verify those against the target repository and its
[SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

The converter does not assign detector precision: a MITRE technique or a valid
output format does not establish a detector's false-positive rate.

## Rule deduplication

Multiple findings can share a MITRE technique (e.g. several priv-esc attempts all → T1611). The skill builds a unique `tool.driver.rules[]` array keyed by technique uid so each technique appears once with its description, and each `result` references the rule by `ruleId`.

## Usage

```bash
# From the repository root in Bash; propagate upstream failures.
set -o pipefail
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python skills/detection/detect-privilege-escalation-k8s/src/detect.py \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py --output findings.sarif
```

Upload is a separate caller-owned step. Use GitHub's documented SARIF upload
workflow after checking the target repository's permissions and consumer
requirements; passing this converter's tests is not proof of a hosted upload.

## Tests

Golden fixture parity: runs the K8s priv-esc golden findings (`../../detection-engineering/golden/k8s_priv_esc_findings.ocsf.jsonl`) through the converter and asserts the output matches a frozen SARIF golden (`../../detection-engineering/golden/k8s_priv_esc_findings.sarif`). Plus unit tests for severity mapping, MITRE rule deduplication, multi-finding handling, edge cases (missing attacks, missing observables, empty input), the SARIF GUID constraint, and CLI failure behavior that preserves prior reports.
