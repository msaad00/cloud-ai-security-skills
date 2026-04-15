# Schema Versioning

This repo has two related but different versioned contracts:

- the repo-owned canonical/native schema version
- the OCSF wire-contract version used by the repo

They are pinned on purpose and should be bumped intentionally, not casually.

## 1. Canonical and native schema version

Canonical and native payloads use:

- `canonical_schema_version`

Current value:

- `2026-04`

## Format

`canonical_schema_version` uses `YYYY-MM`, but it is **not** a calendar roll.

It changes only when the canonical/native contract changes in a way downstream
operators may need to review.

That means:

- the version may stay the same across many releases
- the version does **not** change every month automatically
- the month stamp is the first release month of that contract version

## What counts as a schema change

Bump `canonical_schema_version` when any of these happen:

- a canonical or native field is added and downstream consumers may need to
  materialize it
- a canonical or native field is renamed
- a field type changes
- a field meaning changes materially
- a record type changes its stable required keys
- a sink, query pack, or native projection changes its documented stable output
  contract

Do **not** bump it for:

- doc-only changes
- test-only changes
- new examples
- internal refactors with identical emitted fields and semantics
- new skills that reuse the existing canonical/native contract without changing
  the contract itself

## Bump policy

When the canonical/native contract changes:

1. add fields before removing old ones
2. document the change in `CHANGELOG.md`
3. update examples in:
   - `NATIVE_VS_OCSF.md`
   - `CANONICAL_SCHEMA.md`
   - any affected `SKILL.md`
4. bump `canonical_schema_version`
5. update or re-freeze golden fixtures where the emitted shape changes

## Stability promise

If two payloads carry the same `canonical_schema_version`, they should be safe
to treat as the same canonical/native contract for:

- field names
- field meanings
- required identity keys
- native output envelopes

Additive optional fields are still schema changes in this repo because
enterprise teams often pin downstream warehouse tables, transforms, and data
dictionaries to the emitted shape.

## 2. OCSF contract version

The repo’s OCSF contract is pinned in:

- `skills/detection-engineering/OCSF_CONTRACT.md`

Current value:

- `1.8.0+mcp.2026.04`

This means:

- `1.8.0` = upstream OCSF base version
- `+mcp.2026.04` = repo-local profile / mapping / frozen-fixture contract

The `+mcp.2026.04` suffix is the repo’s own compatibility marker for:

- local mapping choices
- profile / label conventions
- pinned fixture expectations
- repo-owned interoperability assumptions layered on top of OCSF 1.8

## When to bump the OCSF contract suffix

Bump the `+mcp.*` suffix when:

- the repo changes an OCSF mapping materially
- an OCSF projection changes class, field placement, or stable semantics
- frozen OCSF golden fixtures are re-cut for contract reasons
- the repo changes the pinned ATT&CK / metadata linkage in a way that affects
  the OCSF contract

Do **not** bump it for:

- doc-only edits
- code refactors with byte-for-byte identical OCSF output
- adding a new skill that simply follows the already-pinned contract

## 3. Relationship between the two versions

The canonical/native version and the OCSF contract version are related, but not
identical.

Examples:

- a native/canonical-only change may bump `canonical_schema_version` without
  changing `1.8.0+mcp.2026.04`
- an OCSF mapping change may require bumping the `+mcp.*` suffix even if the
  canonical schema remains stable
- a broad cross-mode change may require both

## 4. Golden fixture versioning

Today the repo versions fixture expectations through:

- the release tag
- the pinned OCSF contract version
- the pinned canonical/native examples in docs and `SKILL.md`

That is enough for now, but the repo does **not** yet ship a separate
fixture-manifest version per skill family. If that becomes necessary later, it
should extend this contract rather than replace it.

## 5. Upgrade path

When introducing a schema-impacting change:

1. make the change additive first where possible
2. document old and new behavior
3. update examples and affected skill docs
4. re-freeze fixtures
5. cut the version bump in the same PR

## 6. OCSF 2.0 note

If the repo adopts OCSF 2.x later:

- the base contract version changes from `1.8.0+...` to `2.x.y+...`
- the migration should be documented as a deliberate upgrade path
- old and new fixture sets should not be mixed invisibly in one contract

Until then, the repo remains explicitly pinned to OCSF 1.8 plus the current
repo-local `+mcp.*` suffix.
