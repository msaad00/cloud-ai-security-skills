# Runner Deployment Verification

This page tracks the difference between:

- a runner template that is shipped and CI-validated
- a runner path that has also been deployed once end to end in a real cloud

Read next:

- [README.md](README.md)
- [../docs/DATA_HANDLING.md](../docs/DATA_HANDLING.md)
- [../docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md)

## Current Status

| Runner | Template shipped | Handler tests | IaC validation in CI | Walkthrough committed | Local emulated end-to-end in CI | Real deploy proof captured | Tracking issue |
|---|---|---|---|---|---|---|---|
| `aws-s3-sqs-detect` | yes | yes | yes | yes | yes (`moto`, ingest leg) | yes (2026-10-07) — [evidence](aws-s3-sqs-detect/README.md#live-deploy-verification-status) | [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) |
| `gcp-gcs-pubsub-detect` | yes | yes | yes | yes | yes (in-process SDK fakes) | not yet (2026-10-07 attempt skipped: test project has billing disabled) | [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) |
| `azure-blob-eventgrid-detect` | yes | yes | yes | yes | yes (in-process SDK fakes) | yes (2026-10-07) — [evidence](azure-blob-eventgrid-detect/README.md#live-deploy-verification-status) | [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) |

Current repo reality:

- all three runner templates are shipped references
- the handlers and infrastructure contracts are validated in CI
- the repo now carries concrete first-event walkthroughs in each runner README
- `scripts/runner_e2e.sh` runs every runner's real handler entrypoints locally
  in CI (see [Local emulated end-to-end](#local-emulated-end-to-end))
- AWS and Azure have a captured real-cloud deploy-and-first-event proof
  (2026-10-07), including a redelivery that the dedupe store suppressed; the
  evidence and the exact commands live in each runner README
- GCP has no real deploy proof yet: the 2026-10-07 attempt was skipped because
  the test project has billing disabled

The GCP proof is the remaining work tracked in `#198` / `#609`.

The live runs surfaced defects the emulated lane could not: an
`azure-data-tables` call that does not exist on the real SDK (the in-process
fake modeled it), a Bicep "FQDN" output that is a URL, and AWS README deploy
parameters that did not match the template. All are fixed alongside the
evidence.

## Local Emulated End-to-End

`scripts/runner_e2e.sh` (workflow `.github/workflows/runner-e2e.yml`, results
in [`../docs/RUNTIME_PROFILES.md`](../docs/RUNTIME_PROFILES.md)) drives each
runner's real handler code with no cloud credentials and no network egress:

| Runner | Trigger delivered | Backend | What is asserted |
|---|---|---|---|
| `aws-s3-sqs-detect` | S3 object-created record | `moto` S3 + SQS | ingest `lambda_handler` runs the real `ingest-cloudtrail-ocsf` skill; one SQS message per object |
| `gcp-gcs-pubsub-detect` | 2nd gen CloudEvents: `google.cloud.storage.object.v1.finalized`, then `google.cloud.pubsub.topic.v1.messagePublished` per detect message | in-process fakes of the GCS, Pub/Sub, and Firestore clients | real `ingest-gcp-audit-ocsf` + `detect-gcp-open-firewall` on the golden fixture; findings topic receives exactly the golden findings once; every redelivery is suppressed by Firestore `create()` conflict |
| `azure-blob-eventgrid-detect` | Event Grid `Microsoft.Storage.BlobCreated` (EventGridSchema) as the Service Bus queue message body | in-process fakes of the `azure.storage.blob`, `azure.servicebus`, `azure.data.tables`, and `azure.identity` clients | real `ingest-azure-activity-ocsf` + `detect-azure-open-nsg` on the golden fixture; Service Bus topic receives exactly the golden findings once; every redelivery is suppressed by the Table Storage dedupe entity |

What this does **not** prove: IAM / RBAC bindings, Eventarc / Event Grid
trigger delivery, function packaging and runtime signatures, retries, quotas,
or SDK behavior beyond the calls the fakes model. Those need the real deploy
proof below. The fakes can also be wrong about the real SDK
surface — the 2026-10-07 Azure live run found exactly that.

## What Counts As Real Deploy Proof

To close `#198`, each runner should have one captured deploy-and-first-event proof:

1. package the runner handlers for the target cloud runtime
2. deploy the infrastructure template
3. configure one real `ingest-*` and one real `detect-*` skill command
4. send one real source event through the trigger path
5. confirm the downstream dedupe + publish path completes
6. record the exact commands, runtime bindings, and evidence back into the runner README

## Prepared Walkthroughs

Each runner README now includes:

- deploy/apply command skeletons with the required inputs
- where the ingest and detect skill commands are bound
- one example source event to send
- the exact evidence to capture on the first successful run

That is intentionally different from claiming the walkthrough has already been
executed in a real cloud. Prepared walkthroughs reduce operator guesswork; the
live proof still requires a real deployment and captured evidence.

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
- a local emulated end-to-end run of every runner in CI

What it still needs is deployment evidence. This page keeps that distinction
explicit so the repo does not imply a stronger operational claim than it can
currently prove.
