# State and Timeline Model

This repo must model both **history** and **current state**.

Security systems break when they only keep "whatever the latest row says now."

That is especially dangerous for:

- identities that are disabled or deleted
- service principals and app credentials that disappear from snapshots
- AI endpoints or models that were present yesterday but not today
- cloud resources that are terminated after suspicious activity

## Core rule

Treat these as different things:

1. **event history**
2. **materialized entity state**
3. **snapshot absence**

They are not interchangeable.

## Event history

Event history is append-only.

Use it for:

- audit trails
- detection correlation
- timeline replay
- evidence generation
- forensic reconstruction

Recommended time fields:

| Field | Meaning |
|---|---|
| `event_time` | when the source says the event happened |
| `observed_time` | when the repo or collector first saw it |
| `ingested_time` | when the event entered the repo pipeline |
| `effective_time` | when a state transition became true, if different from `event_time` |

All normalized time fields should be:

- UTC
- epoch milliseconds
- preserved as raw source timestamps when available

## Materialized entity state

Entity state is the latest derived view for a stable entity key.

Use it for:

- current inventory
- status dashboards
- access reviews
- "show me what exists now"
- remediation target selection

Recommended fields:

| Field | Meaning |
|---|---|
| `entity_uid` | stable deterministic key for the entity |
| `provider` | AWS, Azure, GCP, Okta, Entra, Workspace, etc. |
| `tenant_uid` / `account_uid` | org, tenant, subscription, account, or project scope |
| `entity_type` | user, group, service_principal, model_endpoint, bucket, cluster, etc. |
| `natural_id` | source-native identifier |
| `status` | current lifecycle state |
| `is_active` | boolean shortcut for operational filters |
| `last_seen_time` | last time the entity was observed in a source event or snapshot |
| `state_last_changed_time` | when the materialized state last changed |
| `deleted_time` / `deactivated_time` | explicit lifecycle end when known |

## Snapshot absence is a signal

If a full snapshot no longer contains an entity that existed before:

- do **not** silently delete the entity
- do **not** assume "not returned" means "never existed"

Instead, treat absence as a state signal.

Recommended values for `status` or `presence_state`:

- `present`
- `missing`
- `disabled`
- `deleted`
- `expired`
- `unknown`

The exact value should match source semantics where the source makes them available.

## Stable entity keys

Use deterministic keys built from:

- provider
- tenant/account/org
- entity type
- natural identifier

That lets the repo keep history even when:

- display names change
- groups are renamed
- resources move between friendly labels
- the same human has different usernames across systems

## Just-in-time vs persistent mode

The same model must work in both:

- **just-in-time / CLI / MCP**
  - return current findings plus last-known context
  - no long-lived store required
- **persistent / continuous**
  - keep append-only events
  - materialize state tables or views
  - emit state transitions and tombstones

The skill code should not change between those modes. Only the runner or sink changes.

## OCSF and non-OCSF compatibility

This model works whether the wire format is:

- native
- canonical
- OCSF
- bridge

Use OCSF event timestamps and IDs when OCSF is the output contract.
Use the same logical fields in canonical/native storage even when the output is not OCSF.

## Operational guidance

When designing a skill or sink:

1. Preserve source-native IDs and timestamps.
2. Derive deterministic event IDs and entity IDs.
3. Never treat disappearance as silent deletion.
4. Keep append-only history separate from current-state views.
5. Make lifecycle transitions explicit.

This is how the repo stays accurate for time series, stateful inventory, replay, SIEM indexing, and persistent security operations.
