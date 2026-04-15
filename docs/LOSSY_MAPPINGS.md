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
| Raw field / context | the original source field or structure |
| Native behavior | what the repo-native projection keeps |
| OCSF behavior | what the OCSF projection keeps |
| Loss / impact | what is reduced, omitted, or flattened |

## ingest-cloudtrail-ocsf

This skill is intentionally selective. It preserves the fields most useful for
cross-cloud activity analysis, but it does not try to serialize the full
CloudTrail payload into either native or OCSF output.

| Raw field / context | Native behavior | OCSF behavior | Loss / impact |
|---|---|---|---|
| `eventID`, `eventName`, `eventSource`, `eventTime`, `recipientAccountId`, `awsRegion` | preserved in normalized fields such as `event_uid`, `operation`, `service_name`, `time_ms`, `account_uid`, `region` | preserved under OCSF metadata, api, cloud, and time fields | mostly semantic remapping, not loss |
| `requestParameters` top-level keys | projected into `resources[]` only at top level | same `resources[]` projection | nested request body detail is not preserved |
| nested `requestParameters` objects | not preserved as structured payload | not preserved | deep request context is intentionally dropped |
| `responseElements` | omitted | omitted | response payload detail is dropped |
| `additionalEventData` | omitted | omitted | free-form supplemental context is dropped |
| session creation time from `userIdentity.sessionContext.attributes.creationDate` | preserved in normalized actor/session context | preserved where mapped through actor/session context | low loss |
| MFA/session flags beyond the current normalized actor/session projection | omitted | omitted | authentication nuance may be reduced |
| repo-native envelope fields such as `canonical_schema_version`, `source.kind`, `source.request_id`, `source.event_id`, `activity_name` | preserved | not first-class OCSF fields | OCSF output loses some repo-owned envelope detail |

### Example

Raw CloudTrail can contain large nested request bodies. The current contract
keeps only the normalized action and resource identity, not the full request.

That is intentional for transport clarity, but it means CloudTrail OCSF/native
output should not be treated as an archival substitute for raw CloudTrail.

## ingest-okta-system-log-ocsf

This skill preserves more vendor detail than the CloudTrail ingester because it
keeps Okta-specific correlation data under `unmapped`.

| Raw field / context | Native behavior | OCSF behavior | Loss / impact |
|---|---|---|---|
| `uuid`, `published`, `eventType`, outcome result | preserved as stable IDs, time, event type, status, and severity | preserved through OCSF metadata, time, status, and class/activity mapping | mostly semantic remapping |
| `transaction.id` and `authenticationContext.rootSessionId` | preserved under `unmapped.okta.*` | preserved under `unmapped.okta.*` | no major native-vs-OCSF loss here |
| `authenticationContext.externalSessionId` | preserved in native `session.uid` | preserved in OCSF `session.uid` | no major loss |
| `client.ipAddress` and `client.userAgent.rawUserAgent` | preserved as `src_endpoint.ip` and `src_endpoint.svc_name` | preserved the same way | fine for transport, but normalized |
| richer `client` structure such as browser / device detail | not preserved as a full object | not preserved as a full object | device/browser nuance is reduced |
| `debugContext.debugData` | omitted | omitted | troubleshooting/debug context is dropped |
| target entity profile detail beyond normalized user/resource/privilege fields | reduced to selected normalized fields | reduced to selected normalized fields | target metadata is flattened |
| repo-native envelope fields such as `canonical_schema_version`, `record_type`, `source_skill`, `output_format` | preserved | not first-class OCSF fields | repo-owned native context is thinner in OCSF |

### Example

Okta session and transaction identifiers survive both modes because the skill
keeps them under `unmapped.okta.*`. That means this skill is not a good example
of “OCSF drops everything vendor-specific.” The real loss is from the raw Okta
payload to the normalized contract, not mostly from native to OCSF.

## ingest-entra-directory-audit-ocsf

The Entra ingester also preserves a useful vendor-specific tail under
`unmapped.entra`, but it still flattens some target and initiator detail.

| Raw field / context | Native behavior | OCSF behavior | Loss / impact |
|---|---|---|---|
| `id`, `correlationId`, `activityDateTime`, `activityDisplayName`, `result` | preserved as event UID, correlation UID, time, operation, and status fields | preserved through metadata/api/time/status fields | mostly semantic remapping |
| `additionalDetails` | preserved under `unmapped.entra.additional_details` | preserved under `unmapped.entra.additional_details` | no major native-vs-OCSF loss here |
| `targetResources[]` primary IDs, names, and types | preserved in normalized `resources[]` | preserved in OCSF `resources[]` | good preservation of identity keys |
| `targetResources[].modifiedProperties` and richer target internals | omitted from normalized resources | omitted | change-specific detail is dropped |
| `initiatedBy.user` / `initiatedBy.app` primary identity fields | normalized into `actor.user` and `src_endpoint` | preserved the same way | mostly semantic remapping |
| richer initiator object detail beyond normalized identity fields | reduced | reduced | some raw Graph detail is flattened |
| repo-native envelope fields such as `canonical_schema_version`, `record_type`, `source_skill`, `output_format` | preserved | not first-class OCSF fields | repo-owned native context is thinner in OCSF |

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
