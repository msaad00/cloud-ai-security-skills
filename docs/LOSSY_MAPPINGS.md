# Lossy Mappings

This file documents where a source payload loses detail when normalized for the
repo’s native or OCSF projections.

The goal is not to claim “OCSF always loses fields.” The honest questions are:

- what is preserved from raw input
- what is normalized
- what is omitted entirely
- what exists only in repo-native context

Use this doc together with:

- [`NATIVE_VS_OCSF.md`](./NATIVE_VS_OCSF.md)
- [`CANONICAL_SCHEMA.md`](./CANONICAL_SCHEMA.md)
- the affected skill’s `SKILL.md`

## Reading the tables

| Column | Meaning |
|---|---|
| Field / context | the original source field or structure |
| Lost at raw -> normalized | detail dropped before either native or OCSF output |
| Preserved in `unmapped.*` | vendor detail kept, but not as first-class normalized fields |
| Native-only | detail kept only in repo-native output |
| Clean in OCSF | detail represented cleanly as standard OCSF fields |

## ingest-cloudtrail-ocsf

This skill is intentionally selective. It preserves the fields most useful for
cross-cloud activity analysis, but it does not try to serialize the full
CloudTrail payload into either native or OCSF output.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `eventID`, `eventName`, `eventSource`, `eventTime`, `recipientAccountId`, `awsRegion` | no | no | no | yes |
| `requestParameters` top-level keys | partial | no | no | partial via `resources[]` |
| nested `requestParameters` objects | yes | no | no | no |
| `responseElements` | yes | no | no | no |
| `additionalEventData` | yes | no | no | no |
| session creation time from `sessionContext.attributes.creationDate` | no | no | no | yes, through normalized actor/session context |
| repo-owned envelope fields such as `canonical_schema_version`, `source.kind`, `source.request_id`, `source.event_id`, `activity_name` | no | no | yes, some fields are native-first | partial |

### Example

Raw CloudTrail can contain large nested request bodies. The current contract
keeps only the normalized action and resource identity, not the full request.

That is intentional for transport clarity, but it means CloudTrail OCSF/native
output should not be treated as an archival substitute for raw CloudTrail.

## ingest-okta-system-log-ocsf

This skill preserves more vendor detail than the CloudTrail ingester because it
keeps Okta-specific correlation data under `unmapped`.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `uuid`, `published`, `eventType`, outcome result | no | no | no | yes |
| `transaction.id` and `authenticationContext.rootSessionId` | no | yes | no | not first-class |
| `authenticationContext.externalSessionId` | no | no | no | yes via `session.uid` |
| `client.ipAddress` and `client.userAgent.rawUserAgent` | no | no | no | yes via `src_endpoint.*` |
| richer `client` browser / device structure | yes, flattened | no | no | no |
| `debugContext.debugData` | yes | no | no | no |
| target entity profile detail beyond normalized user/resource/privilege fields | partial | no | no | partial |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source_skill`, `output_format` | no | no | yes | no |

### Example

Okta session and transaction identifiers survive both modes because the skill
keeps them under `unmapped.okta.*`. That means this skill is not a good example
of “OCSF drops everything vendor-specific.” The real loss is from the raw Okta
payload to the normalized contract, not mostly from native to OCSF.

## ingest-entra-directory-audit-ocsf

The Entra ingester also preserves a useful vendor-specific tail under
`unmapped.entra`, but it still flattens some target and initiator detail.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `id`, `correlationId`, `activityDateTime`, `activityDisplayName`, `result` | no | no | no | yes |
| `additionalDetails` | no | yes | no | not first-class |
| `targetResources[]` primary IDs, names, and types | no | no | no | yes |
| `targetResources[].modifiedProperties` and richer target internals | yes | no | no | no |
| `initiatedBy.user` / `initiatedBy.app` primary identity fields | no | no | no | yes via normalized actor/src fields |
| richer initiator object detail beyond normalized identity fields | partial | no | no | partial |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source_skill`, `output_format` | no | no | yes | no |

## Current scope

This file starts with:

- CloudTrail
- Okta System Log
- Entra directoryAudit

Those are the highest-signal examples for the current repo because they cover:

- a source where raw -> normalized is intentionally selective
- two identity sources where vendor detail is partly preserved under `unmapped`

More ingest skills should be added here over time, but the initial goal is to
make the cost of normalization explicit instead of leaving it implicit.
