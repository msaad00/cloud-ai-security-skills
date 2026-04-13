# References — ingest-vpc-flow-logs-gcp-ocsf

## Source formats and schemas

- **GCP VPC Flow Logs record format** — https://cloud.google.com/vpc/docs/about-flow-logs-records
- **Cloud Logging LogEntry** — https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
- **OCSF schema** — https://schema.ocsf.io/1.8.0/

## Required permissions

None for the ingestor itself. Upstream collection is handled by Cloud Logging exports or API reads outside this skill.
