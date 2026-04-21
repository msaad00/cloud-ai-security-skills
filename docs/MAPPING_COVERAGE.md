# Mapping Coverage Audit

High-signal OCSF mapping audit across the shipped ingesters. This complements
[`SCHEMA_COVERAGE.md`](./SCHEMA_COVERAGE.md): `SCHEMA_COVERAGE.md` explains the
shape trade-offs in more narrative detail, while this file answers the issue
`#272` question directly:

- which raw vendor fields already land in OCSF
- which only land partially
- which are still dropped even though an OCSF slot or `unmapped.*` preservation
  path exists
- which detector families those gaps still block

## Status legend

- `✅ mapped` — field lands cleanly in OCSF output today
- `⚠️ partial` — field is reduced, flattened, or only partly preserved
- `❌ dropped` — field does not survive the current OCSF path

## Detector roll-up

| Detector or workstream | Blocking ingest gaps |
|---|---|
| `detect-container-escape-k8s` follow-up (`#298`) | K8s audit does not project exec/deployer correlation context directly; Falco/Tracee still arrive as secondary detector input rather than through a first-class ingester |
| AWS P0 detector wave (`#253`) | CloudTrail `requestParameters`, `responseElements`, `additionalEventData`, and `tlsDetails` stay selective or dropped |
| Deeper K8s RBAC analysis | K8s audit `requestObject` / `responseObject` are preserved under `unmapped.k8s.*`, but not elevated into richer normalized fields yet |
| Entra privilege-escalation depth | Entra `modifiedProperties` and richer initiator / app detail are still dropped or flattened |
| GCP privilege / egress depth | GCP audit `request`, `response`, `serviceData`, and `metadata` protobuf bodies are still dropped |
| Azure activity depth | Azure `properties.*` beyond coarse status / detail remains dropped |
| Workspace MFA / device posture expansion | Workspace event parameters are preserved under `unmapped.*`, but not normalized into first-class fields |
| MCP drift / prompt-injection follow-ons | MCP raw request / body payloads remain native-only rather than first-class OCSF fields |

## ingest-okta-system-log-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| `uuid`, `published`, `eventType`, outcome | `metadata.uid`, `time`, `api.operation`, `status_id` | `✅ mapped` | No |
| `authenticationContext.externalSessionId` | `session.uid` | `✅ mapped` | No |
| `transaction.id`, `authenticationContext.rootSessionId` | `unmapped.okta.*` | `⚠️ partial` | Not today; could sharpen session-chain correlation |
| `debugContext.debugData` | no slot; not preserved today | `❌ dropped` | Potentially blocks richer auth abuse triage |

## ingest-cloudtrail-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| `eventID`, `eventName`, `eventSource`, `eventTime`, `recipientAccountId`, `awsRegion` | `metadata.uid`, `api.operation`, `api.service.name`, `time`, `cloud.*` | `✅ mapped` | No |
| top-level `requestParameters` identity fields | `resources[]` and normalized resource projection | `⚠️ partial` | Some AWS detectors need deeper request bodies |
| nested `requestParameters`, `responseElements`, `additionalEventData`, `tlsDetails` | no current slot / not preserved under `unmapped.aws.*` | `❌ dropped` | Yes for richer AWS discovery, egress, and trust-edit detections |

## ingest-k8s-audit-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| `auditID`, `verb`, `user.*`, `sourceIPs`, `userAgent`, `objectRef.*` | `metadata.uid`, `api.operation`, `actor`, `src_endpoint`, `resources[]` | `✅ mapped` | No |
| `requestObject`, `responseObject`, full `objectRef` | `unmapped.k8s.*` | `⚠️ partial` | Not blocked for current detectors; deeper RBAC / patch-diff analytics still need promotion |
| stage-level envelope detail outside the terminal record | none | `❌ dropped` | Not currently blocking |

## ingest-entra-directory-audit-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| `id`, `correlationId`, `activityDateTime`, `activityDisplayName`, `result` | `metadata.uid`, `api.request.uid`, `time`, `api.operation`, `status_id` | `✅ mapped` | No |
| `additionalDetails` | `unmapped.entra.additional_details` | `⚠️ partial` | Usually not; helpful for future credential / federation depth |
| `targetResources[].modifiedProperties` | no current slot | `❌ dropped` | Yes for richer privilege and app-change diffing |
| richer `initiatedBy.app` sub-structure | flattened into actor identity only | `⚠️ partial` | Can block app-vs-user attribution depth |

## ingest-gcp-audit-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| `timestamp`, `serviceName`, `methodName`, `resourceName`, project / location labels | `time`, `api.service.name`, `api.operation`, `resources[]`, `cloud.*` | `✅ mapped` | No |
| `authenticationInfo.*`, `requestMetadata.callerIp`, `callerSuppliedUserAgent` | `actor`, `src_endpoint` | `✅ mapped` | No |
| `request`, `response`, `serviceData`, `metadata` bodies | no current slot / not preserved under `unmapped.gcp.*` | `❌ dropped` | Yes for richer IAM, egress, and admin-action detections |

## ingest-azure-activity-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| `eventDataId`, `correlationId`, `time`, `operationName`, `resourceId`, region / subscription context | `metadata.uid`, `api.request.uid`, `time`, `api.operation`, `resources[]`, `cloud.*` | `✅ mapped` | No |
| `claims`, `caller`, source IP | `actor`, `src_endpoint.ip` | `✅ mapped` | No |
| `properties.statusCode`, `properties.statusMessage` | `status_id`, `status_detail` | `⚠️ partial` | Usually not |
| broader `properties.*` free-form content | no current slot | `❌ dropped` | Yes for deeper Azure admin / correlation detections |

## ingest-google-workspace-login-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| login event identity, source IP, session handle | `actor`, `src_endpoint`, `session.uid` | `✅ mapped` | No |
| event parameters and login metadata | `unmapped.google_workspace_login.*` | `⚠️ partial` | Not blocked for shipped login detector; future device-posture logic needs promotion |
| unsupported Admin SDK event families | not ingested | `❌ dropped` | Yes for non-login Workspace detections |

## ingest-mcp-proxy-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| `timestamp`, `session_id`, `method`, `direction`, tool fingerprints | MCP custom profile over OCSF Application Activity | `✅ mapped` | No |
| raw `params` / tool body payloads | native-only | `⚠️ partial` | Can block richer tool-result or output-handling detectors |
| generic JSON-RPC wrapper fields outside the MCP profile | not normalized | `❌ dropped` | Potentially blocks deeper protocol anomaly detection |

## ingest-vpc-flow-logs-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| tuple, ports, protocol, bytes, packets, action | OCSF network activity fields | `✅ mapped` | No |
| VPC / subnet / instance / direction context | normalized cloud/source context | `⚠️ partial` | Not blocked for current lateral-movement rules |
| exporter-specific extended tuple fields | not preserved | `❌ dropped` | Could block finer-grained network analytics |

## ingest-vpc-flow-logs-gcp-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| connection tuple, disposition, bytes / packets | OCSF network activity fields | `✅ mapped` | No |
| project, VPC, subnet, reporter, region context | normalized cloud/source context | `⚠️ partial` | Usually not |
| exporter wrapper detail beyond the normalized tuple | not preserved | `❌ dropped` | Could block network-forensics depth |

## ingest-nsg-flow-logs-azure-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| source, destination, ports, protocol, decision, counters | OCSF network activity fields | `✅ mapped` | No |
| NSG resource ID, rule, subscription, location | normalized source/cloud context | `⚠️ partial` | Usually not |
| outer flow-group wrapper detail | not preserved | `❌ dropped` | Low current detector impact |

## ingest-guardduty-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| finding identity, title, description, severity, timestamps | OCSF Detection Finding fields | `✅ mapped` | No |
| primary resource identity (`AccessKeyDetails`, `InstanceDetails`, `EksClusterDetails`) | summarized `resources[]` | `⚠️ partial` | Could reduce future resource-specific pivots |
| deeper `service.*` provider detail | not preserved | `❌ dropped` | Not blocking current passthrough use |

## ingest-security-hub-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| finding ID, title, description, types, timestamps, severity | OCSF Detection Finding fields | `✅ mapped` | No |
| `Compliance.Status`, `SecurityControlId`, status reasons | normalized compliance fields | `⚠️ partial` | Usually not |
| wider ASFF note / workflow / provider metadata | not preserved | `❌ dropped` | Limits deeper triage correlation |

## ingest-gcp-scc-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| finding name, category, description, time, severity, state, class, resource | OCSF Detection Finding fields | `✅ mapped` | No |
| project identity and state/class labels | normalized cloud/source context | `⚠️ partial` | Usually not |
| richer SCC document detail beyond the headline finding | not preserved | `❌ dropped` | Could block future SCC-native enrichment |

## ingest-azure-defender-for-cloud-ocsf

| Raw vendor field | OCSF 1.8 destination | Status | Blocks detector? |
|---|---|---|---|
| alert ID, title, description, severity, time, resource ID / location | OCSF Detection Finding fields | `✅ mapped` | No |
| compliance status, control ID, remediation hints | normalized compliance/source context | `⚠️ partial` | Usually not |
| broader `properties.*` alert body | not preserved | `❌ dropped` | Limits future Azure finding enrichment |

## Next ingest follow-ups

1. Preserve high-value dropped fields under `unmapped.<vendor>.*` before inventing new normalized fields.
2. Promote only the detector-relevant subset into first-class OCSF/native fields once a detector or view path actually consumes it.
3. Keep deterministic `metadata.uid` / `finding_uid` stable when widening coverage.
4. Regenerate frozen fixtures and run the OCSF validator on every ingester touched.
