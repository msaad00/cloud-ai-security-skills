# Native, Canonical, OCSF, and Bridge Modes

`cloud-ai-security-skills` must work **with or without OCSF**.

That is not a soft preference. It is the repo contract.

## The four schema modes

| Mode | Purpose | When to use it |
|---|---|---|
| **native** | Preserve the source payload shape and natural identifiers | source fidelity matters most, the vendor schema is the contract, or OCSF would be lossy |
| **canonical** | Normalize into the repo's stable internal model | internal-only storage and join model; not emitted directly today. `native`, `ocsf`, and `bridge` are projections of canonical |
| **ocsf** | Emit native OCSF classes, profiles, or extensions | SIEM interoperability, cross-vendor correlation, downstream OCSF consumers, or shared wire contracts between skills |
| **bridge** | Emit an OCSF-friendly event while preserving the native or canonical artifact under `unmapped` or an explicit sidecar field | OCSF helps transport/search, but the source or evidence shape still carries important detail |

The rule is simple:

1. **Keep source truth.**
2. **Stabilize the repo around a canonical internal model.**
3. **Use OCSF where it adds interoperability.**
4. **Use bridge mode when both are needed.**

## Source-specific ingestion

Every source has its own:

- field names
- event taxonomy
- enum values
- timestamps
- pagination model
- nested payloads
- natural identifiers
- ordering and retry behavior

So ingest skills must never pretend all vendors look alike.

The ingest contract is:

`raw source payload -> canonical internal model -> native | ocsf | bridge output`

That lets the repo stay accurate for Okta, Entra, Google Workspace, AWS, Azure, GCP, Kubernetes, AI service APIs, and any later vendor without flattening away source truth.

## What stays stable across modes

No matter which mode a skill uses, the repo should preserve:

- source-native identifiers when they exist
- UTC timestamps and epoch-ms normalized time fields
- actor, target, provider, tenant/account, and resource keys
- deterministic event and finding identity
- explicit lifecycle status where the source exposes it
- enough raw context to explain how the normalized record was produced

## Canonical model expectations

The repo should treat the canonical internal model as the stable contract for:

- database tables and views
- entity materialization
- metrics
- indexes
- search filters
- joins across vendors and clouds
- UI or reporting surfaces

That means:

- do **not** make OCSF the only storage schema
- do **not** let every skill invent its own internal column names
- do **not** rename canonical fields casually

If the repo needs to change a canonical field, treat it like a migration:

- additive first
- deprecate second
- remove later

## Skill contract requirements

Every shipped skill should document:

- accepted input modes:
  - `raw`
  - `canonical`
  - `ocsf`
- supported output modes:
  - `native`
  - `ocsf`
  - `bridge`
- whether the mapping is lossless or lossy
- which source-native fields are preserved
- what the stable output identity fields are

## Practical defaults by layer

| Layer | Recommended default |
|---|---|
| **ingest** | `raw -> canonical`, plus optional `ocsf` or `bridge` output |
| **discover** | `canonical` or `native`, plus optional OCSF inventory/evidence bridge |
| **detect** | `canonical` or `ocsf` input; emit `ocsf` when it fits, or a documented canonical/native finding shape otherwise |
| **evaluate** | `canonical` or `ocsf` input; keep framework outputs deterministic and machine-readable |
| **view** | convert from canonical or OCSF into target formats such as SARIF, Mermaid, dashboards, or evidence exports |
| **remediate** | prefer canonical plus preserved native identifiers; never depend only on a lossy transformed view |

## OCSF policy

The repo remains **OCSF-first for shared pipelines**, but **not OCSF-only**.

Use OCSF when:

- a native class/profile/extension fits cleanly
- the output is headed to a SIEM, lake, MCP-delivered workflow, or cross-vendor detection pipeline
- a downstream tool benefits from standard indexing and correlation

Do not force OCSF when:

- the source schema carries important semantics that would be lost
- the artifact is inventory/evidence/BOM-shaped and OCSF does not model it cleanly enough yet
- the canonical or native output is the more accurate operational contract

## Compatibility guidance

The repo can support all three operational styles:

- **native-only** for source fidelity and vendor-native workflows
- **canonical-first** for state stores, metrics, evidence, and stable internal consumers
- **OCSF-first** for interoperability, SIEMs, and shared pipelines

The correct choice depends on the skill and the downstream consumer, not on ideology.

## Current rollout status

Implemented dual-mode skills today:

- `ingest-cloudtrail-ocsf`
- `ingest-vpc-flow-logs-ocsf`
- `ingest-k8s-audit-ocsf`
- `detect-lateral-movement`
- `detect-privilege-escalation-k8s`
- `detect-sensitive-secret-read-k8s`

Implemented native-first with bridge skills today:

- `discover-environment`
- `discover-control-evidence`
- `discover-cloud-control-evidence`

The remaining skills now declare their supported `input_formats` and
`output_formats` explicitly in `SKILL.md`, even where only one format is
implemented today. That keeps the contract honest while the rollout continues
skill-by-skill.
