# Azure Activity Log → OCSF 1.8 API Activity (class 6003) field map

Raw Azure Activity Log records land with the JSON shape Azure Monitor exports
to Event Hubs, Storage, or Log Analytics. The table below pins the exact
mapping this skill applies. Claude loads it on demand; the main `SKILL.md`
stays focused on triggers and guardrails.

## Categories handled

Administrative, Service Health, Resource Health, Alert, Autoscale,
Recommendation, Security, Policy.

## Record → OCSF field mapping

| Raw Azure field | OCSF 1.8 field | Notes |
|---|---|---|
| `caller` / `claims.upn` / `claims.appid` | `actor.user.name`, `actor.user.uid` | Prefer UPN when present; fall back to appid for service principals |
| `callerIpAddress` | `src_endpoint.ip` | IPv4 / IPv6 both accepted as-is |
| `operationName.value` | `api.operation` | The full operation name (e.g. `Microsoft.Storage/storageAccounts/write`) |
| `operationName.value` (verb prefix) | `activity_id` | `Create` → 1, `Read` → 2, `Update` → 3, `Delete` → 4, other → 0 |
| `properties.statusCode` | `status_id` | `Success`/`Accepted` → 1, `Failed`/`Denied` → 2, unknown → 0 |
| `resourceId` | `resource.uid` | ARM resource URI |
| `resourceType` | `resource.type` | e.g. `Microsoft.Compute/virtualMachines` |
| `subscriptionId` | `cloud.account.uid` | |
| `tenantId` | `cloud.org.uid` | |
| `eventTimestamp` | `time` | ISO 8601 → epoch milliseconds |
| `correlationId` | `metadata.correlation_uid` | For cross-event joins |
| `resourceGroup` | `resource.labels.resource_group` | Custom label preserved |

## Output formats

- `--output-format ocsf` — emits OCSF 1.8 API Activity (class 6003) JSONL.
- `--output-format native` — emits the canonical internal event shape (same
  fields, Azure-native names preserved) for operators who want full fidelity.

## Activity verb inference

`activity_id` is derived from the verb prefix in `operationName.value`:

```
Microsoft.Storage/storageAccounts/write  →  Update (3)
Microsoft.Storage/storageAccounts/read   →  Read (2)
Microsoft.Storage/storageAccounts/delete →  Delete (4)
Microsoft.Authorization/roleAssignments/write → Update (3)
```

Operations without a clean verb prefix default to `activity_id: 0` (Other).

## Edge cases and limits

- **Policy Denied events** — `status_id: 2 (Failure)` regardless of HTTP status.
- **Service Health / Resource Health** — `category` is preserved under
  `metadata.original_category` since OCSF has no direct mapping.
- **Bulk batches** — each Event Hubs `records[]` entry is emitted as a
  separate OCSF event; `metadata.correlation_uid` stays constant across the batch.
- **Diagnostic / metric logs** are NOT handled here — see the skill frontmatter
  negative trigger.

## Upstream references

- Azure Monitor export schema: <https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema>
- OCSF 1.8 API Activity (6003): <https://schema.ocsf.io/1.8.0/classes/api_activity>
