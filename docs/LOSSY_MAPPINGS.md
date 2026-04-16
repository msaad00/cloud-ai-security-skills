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
- [`NORMALIZATION_REFERENCE.md`](./NORMALIZATION_REFERENCE.md)
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

## ingest-vpc-flow-logs-ocsf

AWS VPC Flow Logs are tuple-based rather than request-shaped. The ingester keeps
the fields needed for flow correlation and disposition, but it does not try to
preserve the full raw line shape.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `account-id`, `interface-id`, `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `start`, `end`, `action` | no | no | no | yes |
| `bytes`, `packets` | no | no | no | yes |
| `vpc-id`, `subnet-id`, `instance-id`, `flow-direction`, `region` | no | no | no | partial via normalized cloud and source context |
| extended tuple fields beyond the normalized connection / traffic model | yes | no | no | no |
| `NODATA` / `SKIPDATA` lines | yes, intentionally skipped | no | no | no |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source.kind`, `disposition` | no | no | yes | partial |

## ingest-guardduty-ocsf

GuardDuty is already a finding-shaped feed, so the OCSF fit is good. The main
loss is the long tail of provider-specific fields that are summarized into
normalized finding metadata rather than preserved verbatim.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `Id`, `Arn`, `Type`, `Title`, `Description`, `AccountId`, `Region` | no | no | no | yes |
| `Severity`, `CreatedAt`, `UpdatedAt`, `Service.EventFirstSeen`, `Service.EventLastSeen` | no | no | no | yes |
| primary resource identity such as `AccessKeyDetails`, `InstanceDetails`, `EksClusterDetails` | partial, reduced to normalized resources | no | no | partial |
| deeper `Service` substructures and provider-specific raw detail beyond normalized evidence / source fields | yes | no | no | no |
| EventBridge wrapper fields around `detail` | yes, envelope stripped | no | no | no |
| repo-owned envelope fields such as `finding_uid`, `canonical_schema_version`, `source.kind` | no | no | yes | partial |

## ingest-security-hub-ocsf

Security Hub findings also fit OCSF Detection Finding well. The main selective
projection happens inside the richer ASFF compliance and provider metadata.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `Id`, `AwsAccountId`, `Title`, `Description`, `Types`, `CreatedAt`, `UpdatedAt` | no | no | no | yes |
| `Severity.Label`, `Severity.Normalized` | no | no | no | yes |
| primary `Resources[]` identity and region context | partial, normalized resource summaries only | no | no | partial |
| `Compliance.Status`, `SecurityControlId` | no | no | no | yes |
| `Compliance.StatusReasons[]` rich objects | partial, flattened into joined reason codes | no | no | partial |
| EventBridge wrapper fields around `detail.findings[]` | yes, envelope stripped | no | no | no |
| other ASFF provider detail such as notes, workflow metadata, product fields, long nested finding blocks | yes | no | no | no |
| repo-owned envelope fields such as `finding_uid`, `canonical_schema_version`, `source.kind` | no | no | yes | partial |

## ingest-gcp-audit-ocsf

The GCP audit ingester is selective in the same way as CloudTrail: it keeps the
parts needed for cross-cloud API activity correlation, not the full raw
`protoPayload`.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `insertId`, `timestamp`, `serviceName`, `methodName`, `resourceName`, `resource.labels.project_id`, `resource.labels.location` | no | no | no | yes |
| `authenticationInfo.principalEmail`, `principalSubject`, `serviceAccountKeyName` | no | no | no | yes |
| `requestMetadata.callerIp`, `callerSuppliedUserAgent` | no | no | no | yes |
| deeper `protoPayload` request / response content beyond normalized service, method, actor, and resource identity | yes | no | no | no |
| non-`google.cloud.audit.AuditLog` entries | yes, intentionally skipped | no | no | no |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source.kind`, `source.insert_id` | no | no | yes | partial |

## ingest-vpc-flow-logs-gcp-ocsf

GCP VPC flow exports are also tuple-shaped. The ingester keeps the fields
needed for network activity analysis and drops the rest of the exporter shape.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| connection tuple fields such as `src_ip`, `dest_ip`, `src_port`, `dest_port`, `protocol`, `start_time`, `end_time`, `disposition` | no | no | no | yes |
| project, VPC, subnet, reporter, region context | no | no | no | partial via normalized cloud and source context |
| traffic counters and bytes | no | no | no | yes |
| other exporter-specific payload structure outside the normalized connection / traffic model | yes | no | no | no |
| rows without a valid `connection` block | yes, intentionally skipped | no | no | no |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source.kind`, `source.reporter` | no | no | yes | partial |

## ingest-gcp-scc-ocsf

Security Command Center findings are normalized cleanly at the headline level,
but the broader SCC finding document is much richer than the current contract.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `name`, `category`, `description`, `eventTime` / `createTime`, `severity`, `state`, `findingClass`, `resourceName` | no | no | no | yes |
| project identity derived from the finding name or resource path | no | no | no | partial via normalized cloud/account fields |
| other SCC finding content beyond the normalized title, severity, state, class, and resource name | yes | no | no | no |
| source-specific state and class labels | no | no | yes as repo-owned source context / observables | partial |
| repo-owned envelope fields such as `finding_uid`, `canonical_schema_version`, `source.kind` | no | no | yes | partial |

## ingest-azure-activity-ocsf

Azure Activity Log maps well to API Activity, but the raw `properties` object is
larger than the normalized contract.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `eventDataId`, `correlationId`, `time`, `operationName`, `resourceId`, subscription and region context | no | no | no | yes |
| actor fields from `claims` / `caller` and source IP | no | no | no | yes |
| `properties.statusCode`, `properties.statusMessage` summarized into `status_id` / `status_detail` | partial | no | no | partial |
| richer `properties.*` content beyond normalized status and resource context | yes | no | no | no |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source.kind`, `source.category` | no | no | yes | partial |

## ingest-azure-defender-for-cloud-ocsf

Defender for Cloud findings preserve the key alert identity and compliance
signals, but not the full raw alert body.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| alert ID, title, description, severity, time, `resourceDetails.id`, `resourceDetails.location` | no | no | no | yes |
| `compromisedEntity`, `remediationSteps`, compliance status, compliance control ID | no | no | no | partial via normalized source/compliance context |
| `resourceDetails` beyond normalized ID / location | partial | no | no | partial |
| other `properties.*` alert detail beyond normalized title, severity, compliance, and remediation fields | yes | no | no | no |
| repo-owned envelope fields such as `finding_uid`, `canonical_schema_version`, `source.kind` | no | no | yes | partial |

## ingest-nsg-flow-logs-azure-ocsf

Azure NSG flow logs are normalized the same way as the other flow exports: keep
the tuple and boundary context, drop the rest of the exporter shape.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| tuple fields such as source, destination, ports, protocol, decision, flow state, bytes and packets | no | no | no | yes |
| NSG resource ID, rule, MAC, location, subscription context | no | no | no | partial via normalized cloud and source context |
| outer record / flow-group wrapper structure | yes, wrapper stripped | no | no | no |
| exporter-specific fields beyond the normalized connection / traffic / source context | yes | no | no | no |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source.kind`, `source.rule` | no | no | yes | partial |

## ingest-k8s-audit-ocsf

Kubernetes audit maps well to API Activity for verb, actor, and object
identity. The main loss is the full request / response body and the long tail
of raw audit metadata.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `auditID`, `verb`, `requestURI`, `user.*`, `sourceIPs`, `userAgent`, `objectRef.*`, `responseStatus.code` | no | no | no | yes |
| service-account namespace derivation and normalized authz labels | no | no | yes, some fields are native-first | partial |
| `requestObject`, `responseObject`, `managedFields`, long raw audit envelope detail | yes | no | no | no |
| `RequestReceived` stage entries | yes, intentionally skipped | no | no | no |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source.kind`, `source.stage` | no | no | yes | partial |

## ingest-google-workspace-login-ocsf

Workspace login audit is one of the better examples of vendor context preserved
under `unmapped` rather than dropped outright.

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `id.time`, `id.uniqueQualifier`, `applicationName`, supported login event names | no | no | no | yes |
| actor, subject user, source IP, session handle | no | no | no | yes |
| event parameters and login-specific raw context | no | yes under `unmapped.google_workspace_login.parameters` | no | not first-class |
| other supported event metadata such as `customerId`, `ownerDomain`, `eventType` | no | yes under `unmapped.google_workspace_login.*` | no | not first-class |
| unsupported Admin SDK events outside the supported login set | yes, intentionally skipped | no | no | no |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `source_skill`, `output_format` | no | no | yes | no |

## ingest-mcp-proxy-ocsf

MCP proxy telemetry is intentionally normalized into the repo's custom MCP
profile over OCSF Application Activity. That means the loss question is less
"OCSF vs native" and more "generic OCSF vs custom MCP profile vs full raw
JSON-RPC body."

| Field / context | Lost at raw -> normalized | Preserved in `unmapped.*` | Native-only | Clean in OCSF |
|---|---|---|---|---|
| `timestamp`, `session_id`, `method`, `direction` | no | no | no | yes via the MCP custom profile |
| tool name, description, schema fingerprint, tool fingerprint | no | no | no | yes via the MCP custom profile |
| raw `params` and `body` payloads | no | no | yes | not first-class |
| generic JSON-RPC wrapper detail not represented in the normalized MCP profile | partial | no | yes | partial |
| repo-owned envelope fields such as `canonical_schema_version`, `record_type`, `profile`, `output_format` | no | no | yes | partial |

## Scope

This file now covers every shipped `ingest-*` normalization skill.

It intentionally does **not** cover the `source-*` adapters because those do
not normalize vendor payloads into native or OCSF contracts. They are raw
query / extraction edges, not schema-projection skills.

When a new ingest skill ships, update this file in the same change so the
auditable loss story stays complete.
