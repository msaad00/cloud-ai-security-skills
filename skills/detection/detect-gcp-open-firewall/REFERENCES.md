# References — detect-gcp-open-firewall

## GCP

- VPC firewall rules overview — https://cloud.google.com/firewall/docs/firewalls
- Firewall rule components (direction, sourceRanges, allowed) — https://cloud.google.com/firewall/docs/firewalls#firewall_rule_components
- Compute Engine API: `firewalls.insert` — https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/insert
- Compute Engine API: `firewalls.patch` — https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/patch
- Cloud Audit Logs: AuditLog message — https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog
- Cloud Audit Logs: types of audit logs — https://cloud.google.com/logging/docs/audit

## MITRE ATT&CK

- T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- TA0001 — Initial Access: https://attack.mitre.org/tactics/TA0001/

## OCSF

- API Activity (class 6003): https://schema.ocsf.io/1.8.0/classes/api_activity (input shape)
- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding (output shape)
- Repo-pinned contract: [`skills/detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)

## Compliance

- CIS GCP Foundations 2.x — sections 3.6 / 3.7 (ensure no firewall rule allows ingress from 0.0.0.0/0 on admin or database ports)
- NIST CSF 2.0 — `PR.AC-05` (Network integrity is protected)

## Related repo skills

- [`ingest-gcp-audit-ocsf`](../../ingestion/ingest-gcp-audit-ocsf/) — upstream
- [`remediate-gcp-firewall-revoke`](../../remediation/remediate-gcp-firewall-revoke/) — paired closed-loop remediator
- [`cspm-gcp-cis-benchmark`](../../evaluation/cspm-gcp-cis-benchmark/) — periodic posture equivalent
