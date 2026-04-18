# References — detect-credential-stuffing-okta

## Source formats and schemas

- **Okta System Log API** — https://developer.okta.com/docs/reference/api/system-log
- **Okta System Log query guide** — https://developer.okta.com/docs/reference/system-log-query/
- **Okta Event Types catalog** — https://developer.okta.com/docs/reference/api/event-types/
- **OCSF 1.8 Authentication (3002)** — https://schema.ocsf.io/1.8.0/classes/authentication
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1110 Brute Force** — https://attack.mitre.org/techniques/T1110/
- **MITRE ATT&CK T1110.003 Password Spraying** — https://attack.mitre.org/techniques/T1110/003/
- **MITRE ATT&CK T1110.004 Credential Stuffing** — https://attack.mitre.org/techniques/T1110/004/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF events from
`ingest-okta-system-log-ocsf`. The ingester's own permissions are documented
in its `REFERENCES.md`.
