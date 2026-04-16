# Runner Deployment Verification

This page tracks the difference between:

- a runner template that is shipped and CI-validated
- a runner path that has also been deployed once end to end in a real cloud

Read next:

- [README.md](README.md)
- [../docs/DATA_HANDLING.md](../docs/DATA_HANDLING.md)
- [../docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md)

## Current Status

| Runner | Template shipped | Handler tests | IaC validation in CI | Real deploy proof captured | Tracking issue |
|---|---|---|---|---|---|
| `aws-s3-sqs-detect` | yes | yes | yes | not yet | [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) |
| `gcp-gcs-pubsub-detect` | yes | yes | yes | not yet | [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) |
| `azure-blob-eventgrid-detect` | yes | yes | yes | not yet | [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) |

Current repo reality:

- all three runner templates are shipped references
- the handlers and infrastructure contracts are validated in CI
- the repo does not yet claim a checked-in live deployment walkthrough for all three clouds

That is the remaining work tracked in `#198`.

## What Counts As Real Deploy Proof

To close `#198`, each runner should have one captured deploy-and-first-event proof:

1. package the runner handlers for the target cloud runtime
2. deploy the infrastructure template
3. configure one real `ingest-*` and one real `detect-*` skill command
4. send one real source event through the trigger path
5. confirm the downstream dedupe + publish path completes
6. write the exact walkthrough and cloud-specific prerequisites back into the runner README

## Cloud-Specific First-Event Checklist

### AWS

- deploy `template.yaml`
- bind the source bucket notification
- upload one object that the ingest handler can read
- confirm:
  - ingest Lambda invoked
  - detect SQS message created
  - detect Lambda invoked
  - DynamoDB dedupe row written
  - SNS publish succeeded

### GCP

- apply `main.tf`
- package and deploy both Cloud Functions
- finalize one object in the source GCS bucket
- confirm:
  - ingest function invoked
  - Pub/Sub detect topic received messages
  - detect function invoked
  - Firestore dedupe document created
  - findings topic publish succeeded

### Azure

- deploy `template.bicep`
- package the handlers into the chosen Azure runtime
- create one blob in the watched container/prefix
- confirm:
  - Event Grid routed the event
  - ingest queue received the message
  - ingest handler ran and enqueued detect work
  - detect handler invoked
  - Table Storage dedupe entity created
  - Service Bus topic publish succeeded

## Why This Page Exists

This repo already has:

- shipped runner templates
- handler tests
- IaC validation

What it still needs is deployment evidence. This page keeps that distinction
explicit so the repo does not imply a stronger operational claim than it can
currently prove.
