# References — ingest-guardduty-ocsf

## AWS GuardDuty

- **Finding format (authoritative)** — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html
  The JSON schema for a GuardDuty finding: `Id`, `Type`, `Severity`, `Resource`, `Service`, `CreatedAt`, `UpdatedAt`. Our ingester targets this exact layout.
- **Finding type format** — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
  Grammar: `<ThreatPurpose>:<ResourceTypeAffected>/<ThreatFamily>.<DetectionMechanism>[!Artifact]`. We split on `:` and `/` to extract the ThreatPurpose prefix for the MITRE tactic lookup and match the full string against our curated technique table.
- **Severity levels** — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html#guardduty_findings-severity
  GuardDuty uses a 1.0–8.9 float scale. Our ingester maps this to OCSF's `severity_id` 1–5 enum per the thresholds documented in SKILL.md.
- **EventBridge event format** — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html
  When GuardDuty delivers findings via EventBridge, the finding body is nested inside a `detail` key with `detail-type: "GuardDuty Finding"`. Our auto-unwrap handles this.
- **GetFindings API** — https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html
  `aws guardduty get-findings` returns `{"Findings": [...]}`. Our auto-unwrap handles this wrapper.

## OCSF 1.8 Detection Finding (2004)

- **Class page** — https://schema.ocsf.io/1.8.0/classes/detection_finding
- **Category: Findings** — https://schema.ocsf.io/1.8.0/categories/findings
- **finding_info.attacks[] layout** — https://schema.ocsf.io/1.8.0/objects/attack
  MITRE ATT&CK lives inside `finding_info.attacks[]` in OCSF 1.8 Detection Finding (not at the event root, which was the OCSF 1.3 Security Finding layout we no longer use).
- **Security Finding (2001) deprecation notice** — https://schema.ocsf.io/1.8.0/classes/security_finding
  Deprecated since OCSF 1.1. Our contract pins Detection Finding 2004 as the only finding class.

## MITRE ATT&CK v14

- **Enterprise matrix** — https://attack.mitre.org/versions/v14/matrices/enterprise/
- **Techniques referenced by the curated type table**:
  - T1071 Application Layer Protocol — https://attack.mitre.org/versions/v14/techniques/T1071/
  - T1071.004 DNS — https://attack.mitre.org/versions/v14/techniques/T1071/004/
  - T1078.004 Cloud Accounts — https://attack.mitre.org/versions/v14/techniques/T1078/004/
  - T1098 Account Manipulation — https://attack.mitre.org/versions/v14/techniques/T1098/
  - T1098.003 Additional Cloud Roles — https://attack.mitre.org/versions/v14/techniques/T1098/003/
  - T1110 Brute Force — https://attack.mitre.org/versions/v14/techniques/T1110/
  - T1046 Network Service Discovery — https://attack.mitre.org/versions/v14/techniques/T1046/
  - T1485 Data Destruction — https://attack.mitre.org/versions/v14/techniques/T1485/
  - T1496 Resource Hijacking — https://attack.mitre.org/versions/v14/techniques/T1496/
  - T1499 Endpoint Denial of Service — https://attack.mitre.org/versions/v14/techniques/T1499/
  - T1530 Data from Cloud Storage Object — https://attack.mitre.org/versions/v14/techniques/T1530/
  - T1552 Unsecured Credentials — https://attack.mitre.org/versions/v14/techniques/T1552/
  - T1552.005 Cloud Instance Metadata API — https://attack.mitre.org/versions/v14/techniques/T1552/005/
  - T1562 Impair Defenses — https://attack.mitre.org/versions/v14/techniques/T1562/
  - T1562.008 Disable or Modify Cloud Logs — https://attack.mitre.org/versions/v14/techniques/T1562/008/
  - T1578 Modify Cloud Compute Infrastructure — https://attack.mitre.org/versions/v14/techniques/T1578/
  - T1580 Cloud Infrastructure Discovery — https://attack.mitre.org/versions/v14/techniques/T1580/
  - T1595 Active Scanning — https://attack.mitre.org/versions/v14/techniques/T1595/
  - T1048 Exfiltration Over Alternative Protocol — https://attack.mitre.org/versions/v14/techniques/T1048/
