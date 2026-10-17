---
name: convert-ocsf-to-mermaid-attack-flow
description: >-
  Convert OCSF 1.8 Detection Findings (class 2004) into Mermaid flowchart
  syntax suitable for inline rendering in PR comments, README files, and
  Markdown wikis. Produces a left-to-right attack flow showing each finding
  as actor → action → target chains, with MITRE ATT&CK technique IDs as
  edge labels and severity-coloured nodes. Each finding retains a separate
  group with its UID on the edge; matching names do not establish a shared
  identity or attack chain. Use when the user mentions Mermaid, attack flow diagram, PR
  comment visualisation, README diagram for a detection result, or wants
  to embed a finding summary in Markdown without uploading SARIF. Do NOT
  use as a SARIF replacement (different audience: humans reading PRs vs
  GitHub code scanning UI). Do NOT use for non-finding OCSF events
  (class_uid != 2004) — those don't have the MITRE / actor / target
  structure this skill expects.
purpose: Convert OCSF 1.8 Detection Findings (class 2004) into Mermaid flowchart syntax suitable for inline rendering in PR comments, README files, and Markdown wikis. Produces a left-to-right attack flow showing each finding...
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

# convert-ocsf-to-mermaid-attack-flow

Cross-vendor view-layer skill: takes OCSF 1.8 Detection Findings on stdin, emits a Mermaid flowchart on stdout. Built once, used by every detection-engineering pipeline that wants to surface findings in a PR comment, a README, or any Markdown surface that renders Mermaid (GitHub does so natively).

## Output shape

A single Mermaid `flowchart LR` block with presentation frontmatter and one
numbered group per input finding. Mermaid 10.5 or newer is required for the
frontmatter configuration. The diagram requests HTML labels for consistent
multiline sizing and uses 20px text, high-contrast cards, and
space above each flow for its heading. Each group has its own actor and target occurrences and one edge
carrying the MITRE technique UID (e.g. `T1611`), detector, and complete
`finding_info.uid` (or an explicit unknown-UID label). Keeping long identifiers
on separate edge-label lines leaves the group headings readable. Headings
include a written severity and any recorded `account.uid`, `cloud.account.uid`,
`tenant.uid`, `cluster.uid`, or `cluster.name` observables. Conflicting context
values are all shown; these labels do not prove identity or join findings.
Node colours reflect that finding alone:

- Red — Critical (5) or Fatal (6)
- Orange — High (4)
- Yellow — Medium (3)
- Grey — Low (2), Informational (1), or Unknown (0)

Output is plain Mermaid by default. Pass `--fenced` to enclose it in triple
backticks with a `mermaid` language tag for inline rendering on GitHub.

Malformed JSON, non-object records, and non-finding classes fail the entire
conversion with a nonzero exit status. No empty or partial diagram is emitted,
and an existing `--output` file is preserved on input failure. Blank input alone
produces a valid “No findings” diagram; it does not establish assessment coverage.

## Field mapping

| OCSF Detection Finding (2004) field | Mermaid element |
|---|---|
| `observables[]` where `name == "actor.name"` | actor node (left side of the chain) |
| `observables[]` where `name` matches `*.name` (target / pod / bucket / secret / tool) | target node (right side) |
| `finding_info.attacks[0].technique.uid` | edge label |
| `finding_info.uid` | visible edge provenance; duplicate or missing UIDs never merge occurrences |
| `severity_id` | node colour within that finding only |
| `metadata.product.feature.name` | detector name after the technique on the edge |

## Example output

The [generated K8s example](../../detection-engineering/golden/k8s_priv_esc_attack_flow.mmd)
contains three finding groups. The repeated service-account name appears once
in each group: the secret-read finding stays High while the other two remain
Critical. Names alone do not establish a shared principal across clusters.

## Identity and evidence boundaries

This view does not correlate findings. Actor and target occurrences remain
separate even when their names, scopes, or finding UIDs match. This avoids
joining different accounts, tenants, clusters, or incomplete observations into
an inferred attack chain. A repeated input record still produces a separate
group and edge. Output is deterministic for the same ordered input.

Account, session, tenant, and cluster context must not substitute for a missing
target. Explicit `target.*` identifiers take precedence over generic name/UID
fallbacks. Missing actors and targets are labelled **Unknown**. A supplied
session UID remains the actor fallback when no actor name is present.

Labels use Mermaid entity encoding for syntax characters; control whitespace
is flattened. Only the renderer inserts line breaks between evidence fields. Input text cannot insert Markdown fences or additional Mermaid
statements. Finding titles are not rendered as tooltips. For full evidence,
inspect the original finding using the edge's visible UID.

## Usage

```bash
# Pipe step in a detection pipeline
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python skills/detection/detect-privilege-escalation-k8s/src/detect.py \
  | python src/convert.py \
  > attack-flow.mmd

# Or paste the output directly into a PR comment / GitHub issue
python src/convert.py < findings.ocsf.jsonl
```

For image exports, fit the canvas to the SVG bounds rather than capturing a
fixed browser viewport. Keep the SVG available for zooming when long identifiers
make the diagram wider than the reading surface.

## Tests

Golden fixture parity against [`../../detection-engineering/golden/k8s_priv_esc_findings.ocsf.jsonl`](../../detection-engineering/golden/k8s_priv_esc_findings.ocsf.jsonl) → [`../../detection-engineering/golden/k8s_priv_esc_attack_flow.mmd`](../../detection-engineering/golden/k8s_priv_esc_attack_flow.mmd). Plus unit tests for severity → class mapping, finding-local identity and severity, unknown targets, literal label encoding, and MITRE label formatting. Node IDs are renderer-owned occurrence indices, never untrusted labels.
