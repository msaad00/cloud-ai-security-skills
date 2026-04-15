# Canonical Schema

The repo must work with or without OCSF.

That means the stable internal contract cannot be "whatever the current OCSF
projection happens to look like." It must be a repo-owned canonical model.

The canonical model is the layer between:

- raw source payloads
- native output
- OCSF output
- bridge output
- persistent DB tables, views, indexes, and metrics

## Rules

1. Raw source truth is preserved.
2. Canonical fields are stable and versioned.
3. `native`, `ocsf`, and `bridge` are projections of canonical.
4. Canonical changes are additive first, then deprecated, then removed.

## Versioning

Canonical payloads should carry:

- `schema_mode: "canonical"`
- `canonical_schema_version`

Current repo-wide canonical schema version:

- `2026-04`

See [`SCHEMA_VERSIONING.md`](./SCHEMA_VERSIONING.md) for bump rules, OCSF pin
semantics, and upgrade guidance.

## Shared core fields

These are the minimum fields every canonical record should preserve where the
source makes them available:

| Field | Meaning |
|---|---|
| `record_type` | repo-owned semantic kind such as `api_activity`, `network_activity`, `detection_finding`, `inventory`, `evidence` |
| `event_uid` or `finding_uid` | deterministic stable identity for replay, dedupe, and joins |
| `provider` | source provider or vendor |
| `tenant_uid` / `account_uid` | tenant, org, subscription, or account key |
| `region` | cloud or locality context when applicable |
| `event_time_ms` / `time_ms` | primary event timestamp in UTC epoch-ms |
| `observed_time_ms` | when the source says the record was observed, if different |
| `ingested_time_ms` | when the repo ingested the record, if materialized later |
| `actor_uid` / `actor_name` | principal identity |
| `session_uid` | stable session or correlation identity |
| `resource_uid` | primary resource identity |
| `status` / `status_id` | normalized success/failure/unknown or equivalent |
| `last_seen_time_ms` | materialized state / inventory last-seen time |
| `is_active` / `presence_state` | current-state and tombstone semantics |

## Layer-specific canonical shapes

### Ingestion

Input:
- `raw`

Canonical output:
- stable provider/account/actor/resource/session/time fields
- source-specific detail preserved under structured canonical keys

Examples:
- `api_activity`
- `network_activity`
- `application_activity`
- `authentication`
- `account_change`

### Detection

Input:
- `canonical`
- optionally `ocsf`
- optionally documented `native`

Canonical detection output:
- `record_type: "detection_finding"`
- deterministic `finding_uid`
- ATT&CK / ATLAS mappings
- severity
- normalized evidence / observables

### Evaluation

Input:
- `raw`
- optionally `canonical`
- optionally `ocsf`

Canonical evaluation output:
- `record_type: "evaluation_result"`
- benchmark/control identifier
- status
- evidence references

### Discovery

Input:
- `raw`
- `canonical`

Canonical discovery output:
- `record_type: "inventory"` or `record_type: "evidence"`
- stable entity keys
- lifecycle state
- last-seen / deactivated semantics

### View

Input:
- usually `ocsf`
- sometimes `canonical`

Output:
- repo-native delivery artifact such as SARIF, Mermaid, dashboards, or reports

### Remediation

Input:
- `raw`
- `canonical`

Canonical remediation output:
- action plan or action result
- stable target IDs
- approval status
- audit references

## Relationship to OCSF

OCSF is a projection target, not the canonical storage model.

Use OCSF when:

- a shared wire format is useful
- a SIEM or lake expects OCSF
- cross-vendor detection benefits from standard fields

Do not force OCSF when:

- native source fidelity matters more
- the payload is inventory/evidence/BOM-shaped and OCSF is a poor fit
- a bridge mode preserves more useful detail

## Relationship to persistence

Persistent stores should prefer canonical fields for:

- tables
- views
- indexes
- metrics
- lifecycle state

That avoids breaking DB schemas every time an output format changes.

## Projection example

The same logical event can exist in three wire shapes while preserving one
canonical contract:

```json
{
  "canonical": {
    "schema_mode": "canonical",
    "canonical_schema_version": "2026-04",
    "record_type": "api_activity",
    "event_uid": "evt-123",
    "provider": "AWS",
    "account_uid": "111122223333",
    "time_ms": 1775797200000,
    "operation": "AssumeRole"
  },
  "native": {
    "schema_mode": "native",
    "record_type": "api_activity",
    "event_uid": "evt-123",
    "provider": "AWS",
    "account_uid": "111122223333",
    "time_ms": 1775797200000,
    "operation": "AssumeRole"
  },
  "ocsf": {
    "class_uid": 6003,
    "category_uid": 6,
    "activity_id": 99,
    "time": 1775797200000,
    "metadata": {"uid": "evt-123"},
    "cloud": {"provider": "AWS", "account": {"uid": "111122223333"}},
    "api": {"operation": "AssumeRole"}
  },
  "bridge": {
    "class_uid": 5040,
    "metadata": {"uid": "evt-123"},
    "unmapped": {
      "canonical": {
        "record_type": "api_activity",
        "provider": "AWS",
        "operation": "AssumeRole"
      }
    }
  }
}
```

The exact projected fields differ by layer, but the rule does not: one
canonical truth, multiple wire formats.

## Current implementation note

The canonical model is now the repo-wide normalization contract:

- ingest and detect are fully dual-mode across the shipped skill set
- discovery is native-first with bridge where useful
- evaluation remains native-first
- sinks and remediation use native repo-owned operational contracts

The repo is no longer in a one-skill pilot stage for canonical-first design.
