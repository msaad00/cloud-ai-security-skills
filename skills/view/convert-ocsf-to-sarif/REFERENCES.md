# References — convert-ocsf-to-sarif

## Standards and schemas

- **SARIF 2.1.0 schema** — https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json
- **SARIF 2.1.0 specification** — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- **OCSF schema** — https://schema.ocsf.io/1.8.0/
- **MITRE ATT&CK** — https://attack.mitre.org/

## Why this skill exists

This skill projects OCSF Detection Findings into a format GitHub code scanning and other SARIF consumers can render directly.

## Required permissions

None. This is a local conversion skill. Uploading the resulting SARIF to GitHub or another system is the caller's responsibility.
