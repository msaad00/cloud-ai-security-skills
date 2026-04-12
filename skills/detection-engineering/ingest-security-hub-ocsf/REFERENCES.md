# References — ingest-security-hub-ocsf

## AWS Security Hub & ASFF

- **ASFF schema (authoritative)** — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
  The full AWS Security Finding Format schema: required fields, types, resource object shape, severity labels, compliance block. Our validator checks every required field before conversion.
- **ASFF required fields** — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-attributes.html
  The set of fields every valid ASFF finding must carry. We enforce the full list in `validate_asff()`.
- **Severity Label + Normalized** — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html#asff-severity
  Label is the preferred enum (INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL); Normalized is a 0-100 integer fallback. We prefer Label, fall back to Normalized.
- **Types taxonomy** — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-type-taxonomy.html
  The `namespace/category/classifier` format used by the Types[] field. We walk this for the `TTPs/<Tactic>/...` pattern to extract MITRE tactics.
- **BatchImportFindings API** — https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html
  Returns `{"Findings": [...]}`. Our auto-unwrap handles this.
- **EventBridge event format** — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html
  `Security Hub Findings - Imported` events carry findings in `detail.findings[]`. Our auto-unwrap handles this.
- **Compliance block** — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html#asff-compliance
  The structure of the Compliance sub-object carried by Config rules and CIS benchmarks. We lift Status, StatusReasons[], and SecurityControlId into observables.

## OCSF 1.8 Detection Finding (2004)

- **Class page** — https://schema.ocsf.io/1.8.0/classes/detection_finding
- **finding_info.attacks[]** — https://schema.ocsf.io/1.8.0/objects/attack
  In OCSF 1.8 Detection Finding, MITRE ATT&CK lives inside `finding_info.attacks[]`. Our ingester emits empty arrays (not nulls) when no MITRE hints are present.

## MITRE ATT&CK v14

- **Tactics list** — https://attack.mitre.org/versions/v14/tactics/enterprise/
  The 14 enterprise tactics, each with its `TA####` uid. Our `_TACTIC_NAME_TO_UID` table covers the full set.
- **Technique format** — https://attack.mitre.org/versions/v14/techniques/enterprise/
  `T####` or `T####.###` for sub-techniques. Our `_TECHNIQUE_RE` regex matches both forms when scanning ProductFields values.

## AWS services that emit ASFF via Security Hub

- **GuardDuty → Security Hub** — https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html
- **Inspector → Security Hub** — https://docs.aws.amazon.com/securityhub/latest/userguide/inspector-controls.html
- **Macie → Security Hub** — https://docs.aws.amazon.com/securityhub/latest/userguide/macie-controls.html
- **Config → Security Hub** — https://docs.aws.amazon.com/securityhub/latest/userguide/config-controls.html
- **Firewall Manager → Security Hub** — https://docs.aws.amazon.com/securityhub/latest/userguide/fms-controls.html
