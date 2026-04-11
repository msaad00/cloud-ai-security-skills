# References — ingest-azure-activity-ocsf

## Source format

- **Azure Activity Log overview** — https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log
- **Activity Log schema** — https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
- **Azure Monitor categories** (Administrative, Service Health, Resource Health, Alert, Autoscale, Recommendation, Security, Policy) — https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log#categories-in-the-activity-log
- **Export to Event Hubs / Storage / Log Analytics** — https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings

## Output format

- **OCSF 1.8 API Activity (class 6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 cloud object** — https://schema.ocsf.io/1.8.0/objects/cloud

## Required Azure permissions (collection)

The skill itself reads from stdin or a local file. To collect Activity
Logs for ingestion, the upstream caller needs one of:

- **Azure built-in Monitoring Reader** — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/monitor#monitoring-reader
- Or (for export via diagnostic settings): **Contributor** on the log destination resource (Storage Account / Event Hub / Log Analytics workspace)

Minimal custom role:

```json
{
  "Name": "activity-log-reader",
  "Actions": [
    "Microsoft.Insights/eventtypes/values/read",
    "Microsoft.Insights/eventtypes/digestEvents/read"
  ],
  "AssignableScopes": ["/subscriptions/{subscriptionId}"]
}
```

## operationName → verb table

Azure operation names follow `PROVIDER/RESOURCETYPE/ACTION`. The skill
classifies by the last meaningful segment, walking past generic `/ACTION`
suffixes (e.g. `RESTART/ACTION` → `RESTART` → Update). The full table
is in `src/ingest.py` (`_VERB_MAP`). Reference for action conventions:
https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

## See also

- `OCSF_CONTRACT.md` (sibling) for the per-skill wire contract
- `ingest-cloudtrail-ocsf` for the AWS equivalent
- `ingest-gcp-audit-ocsf` for the GCP equivalent
