# References — ingest-entra-directory-audit-ocsf

## Source formats and schemas

- **Microsoft Graph list directoryAudits** — https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0
- **Microsoft Graph `directoryAudit` resource type** — https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0
- **Microsoft Graph `targetResource` resource type** — https://learn.microsoft.com/en-us/graph/api/resources/targetresource?view=graph-rest-1.0
- **Microsoft Entra audit log categories and activities** — https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities

## Output format

- **OCSF 1.8 Application Activity category** — https://schema.ocsf.io/
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 Actor object** — https://schema.ocsf.io/1.8.0/objects/actor

## Collection guidance

The skill itself reads JSON from stdin or local files and does not call
Microsoft Graph. Upstream collectors should:

- preserve raw `id`, `correlationId`, `activityDateTime`, and target resource IDs
- keep `activityDisplayName`, `operationType`, `initiatedBy`, and `targetResources` unmodified
- follow Graph pagination and filtering outside this skill when exporting large audit ranges

This first slice intentionally supports a narrow, verified activity family. New
activity names should only be added after checking real Graph responses and the
official Microsoft Entra activity reference.
