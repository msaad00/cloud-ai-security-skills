# Architecture

This page is a one-screen summary. The load-bearing design contract —
guarantees, invariants, OCSF applicability per layer, and roadmap anchors —
lives in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Mental model

Seven skill layers, one shared skill bundle contract, many runtime surfaces.

The repo ships **134 skills** across these seven layers: 25 ingest skills plus 4 `source-*` adapters, 5 discover, 71 detect, 12 evaluate, 12 remediate, 2 view, and 3 output sinks. The authoritative per-skill registry is [`docs/framework-coverage.json`](docs/framework-coverage.json); `scripts/validate_doc_counts.py` gates this paragraph against it in CI.

| Layer | Directory | Responsibility | Default output |
|---|---|---|---|
| L1 Ingest | `skills/ingestion/` | raw source → normalized stream; `source-*` adapters replay warehouse rows | OCSF 1.8 |
| L2 Discover | `skills/discovery/` | inventory, AI BOM, control evidence, graph context | native / CycloneDX |
| L3 Detect | `skills/detection/` | deterministic attack-pattern findings with MITRE ATT&CK / ATLAS | OCSF Detection Finding 2004 |
| L4 Evaluate | `skills/evaluation/` | benchmark and posture checks (CIS, K8s, containers, AI runtime, NIST AI RMF) | native; OCSF 2003 in `evaluate-cis-aws-foundations-ocsf` |
| L5 Remediate | `skills/remediation/` | HITL-gated writes, dry-run default, dual audit, re-verify | native audit records |
| L6 View | `skills/view/` | render findings for humans and code scanning | SARIF · Mermaid |
| L7 Output | `skills/output/` | append-only persistence sinks | pass-through |

`skills/detection-engineering/` is not a layer: it holds the pinned
[`OCSF_CONTRACT.md`](skills/detection-engineering/OCSF_CONTRACT.md) and the
frozen golden fixtures that pin the wire shape. The
browsable per-skill catalog is [`skills/README.md`](skills/README.md) and
[`docs/SKILL_INDEX.md`](docs/SKILL_INDEX.md).

## How skills compose

Each skill is a standalone Python bundle (`SKILL.md` + `src/` + `tests/` +
`REFERENCES.md`) that reads JSONL on stdin and writes JSONL on stdout, so
layers compose with Unix pipes:

```bash
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py audit.jsonl \
  | python skills/detection/detect-privilege-escalation-k8s/src/detect.py \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py \
  > findings.sarif
```

The closed loop — detect → HITL gate → remediate → dual audit → re-verify —
is drawn in [`docs/images/closed-loop-flow.svg`](docs/images/closed-loop-flow.svg)
and specified in [`docs/HITL_POLICY.md`](docs/HITL_POLICY.md) and
[`docs/REMEDIATION_VERIFICATION.md`](docs/REMEDIATION_VERIFICATION.md).

## Edge and runtime

- **Sources and sinks** — `source-*` adapters pull warehouse or object-store
  rows; `sink-*` adapters persist outputs. Neither normalizes payloads.
- **Query packs** — warehouse-native SQL that mirrors detection patterns for
  Snowflake, Databricks, or ClickHouse.
- **Runtime surfaces** — CLI, CI, MCP, webhook/queue runners, and the Python
  library all invoke the same skill bundles. Wrappers add orchestration, not a
  second implementation.

## Where to go next

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full design contract and
  invariants.
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — why the contract
  looks the way it does.
- [`docs/SCHEMA_COVERAGE.md`](docs/SCHEMA_COVERAGE.md) — per-source schema
  coverage tables.
- [`docs/FRAMEWORK_MAPPINGS.md`](docs/FRAMEWORK_MAPPINGS.md) — MITRE ATT&CK,
  CIS, NIST coverage per skill.
- [`SECURITY_BAR.md`](SECURITY_BAR.md) — skill security contract.
