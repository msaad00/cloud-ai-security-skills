# References — detect-azure-open-nsg

## Azure

- Network Security Group security rules — https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
- Security rule properties (`SecurityRulePropertiesFormat`) — https://learn.microsoft.com/en-us/rest/api/virtualnetwork/security-rules/create-or-update
- Service tags (`Internet`, `VirtualNetwork`, `AzureLoadBalancer`) — https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview
- Azure Activity Log schema — https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
- `Microsoft.Network/networkSecurityGroups/securityRules/write` operation listing — https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/networking

## MITRE ATT&CK

- T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- TA0001 — Initial Access: https://attack.mitre.org/tactics/TA0001/

## OCSF

- API Activity (class 6003): https://schema.ocsf.io/1.8.0/classes/api_activity (input shape)
- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding (output shape)
- Repo-pinned contract: [`skills/detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)

## Compliance

- CIS Azure Foundations 2.x — section 6 (Networking; ensure no NSG allows ingress from `Internet` / `*` / `0.0.0.0/0` / `::/0` on admin or database ports)
- NIST CSF 2.0 — `PR.AC-05` (Network integrity is protected)

## Related repo skills

- [`ingest-azure-activity-ocsf`](../../ingestion/ingest-azure-activity-ocsf/) — upstream
- [`remediate-azure-nsg-revoke`](../../remediation/remediate-azure-nsg-revoke/) — paired closed-loop remediator
- [`cspm-azure-cis-benchmark`](../../evaluation/cspm-azure-cis-benchmark/) — periodic posture equivalent
