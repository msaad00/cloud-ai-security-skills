# References — cspm-azure-cis-benchmark

## Standards implemented

- **CIS Microsoft Azure Foundations Benchmark v2.1** — https://www.cisecurity.org/benchmark/azure
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework
- **ISO/IEC 27001:2022** — https://www.iso.org/standard/27001

The full v2.1 benchmark has 90+ controls. This skill implements **6
high-impact checks** covering Storage and Networking. Identity / Logging /
AI Foundry controls are tracked in the Roadmap section of
[`SKILL.md`](SKILL.md).

## Azure APIs read

| Section | Provider | Method | Why |
|---|---|---|---|
| Storage | `Microsoft.Storage` | `storageAccounts.list` | HTTPS-only (CIS 2.2), public blob (CIS 2.3), network rules (CIS 2.4) |
| Networking | `Microsoft.Network` | `networkSecurityGroups.listAll`, `networkWatchers.listAll` | Unrestricted SSH/RDP (CIS 4.1, 4.2), NSG flow logs (CIS 4.3) |

## Required role

The Azure built-in **Reader** role covers every API this skill calls:
https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general#reader

If you want a tighter custom role, the minimal action set is:

```json
{
  "Name": "cspm-azure-cis-benchmark-reader",
  "Actions": [
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkWatchers/read"
  ],
  "AssignableScopes": ["/subscriptions/{subscriptionId}"]
}
```

## SDKs

- **azure-identity** — https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme
- **azure-mgmt-storage** — https://learn.microsoft.com/en-us/python/api/overview/azure/storage
- **azure-mgmt-network** — https://learn.microsoft.com/en-us/python/api/overview/azure/network

Authentication uses `DefaultAzureCredential`, so the skill works with
Azure CLI login (`az login`), managed identity, environment variables,
or Visual Studio Code credential without code changes.
