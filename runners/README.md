# Runners

Runners are the persistent edge components around the stateless skills.

They own:
- source subscriptions and queue triggers
- checkpointing and replay position
- dedupe tables or sink merge semantics
- retry / DLQ behavior
- sink writes and alert fan-out

They do **not** change the skill contract. The same `SKILL.md + src/ + tests/`
bundle should still run unchanged from the CLI, CI, MCP, or a persistent loop.

Read next:

- [DEPLOYMENT_VERIFICATION.md](DEPLOYMENT_VERIFICATION.md)
- [../docs/DATA_HANDLING.md](../docs/DATA_HANDLING.md)

## Shipped reference runners

- [`aws-s3-sqs-detect`](aws-s3-sqs-detect/): S3 object create trigger -> ingest
  Lambda -> SQS detect queue -> detect Lambda -> DynamoDB dedupe -> SNS publish
- [`gcp-gcs-pubsub-detect`](gcp-gcs-pubsub-detect/): GCS finalize trigger ->
  ingest Cloud Function -> Pub/Sub detect topic -> detect Cloud Function ->
  Firestore dedupe -> findings topic
- [`azure-blob-eventgrid-detect`](azure-blob-eventgrid-detect/): Blob create ->
  Event Grid -> ingest queue -> ingest handler -> detect queue -> detect
  handler -> Table Storage dedupe -> Service Bus topic
- [`webhook-receiver`](webhook-receiver/): vendor-neutral HTTP receiver →
  any-source POST → shipped ingest skill → fan-out to S3 / Snowflake /
  ClickHouse sinks. Default-deny routing, HMAC + bearer auth, single-process
  FastAPI app deployable on App Runner / Cloud Run / Container Apps / Kubernetes.
- [`mcp-sse`](mcp-sse/): remote MCP SSE transport for the skills server —
  Dockerfile, Helm chart, and docker-compose packaging so agents can reach the
  same MCP tool surface over the network instead of stdio.

This is a reference template, not a multi-tenant managed service. Operators still
own packaging, deployment, sink wiring, IAM review, and environment-specific
controls.

## Live Deployment Status

All five runners (the three cloud detect pipelines, the webhook receiver, and
the MCP SSE transport) are shipped and CI-validated.

`aws-s3-sqs-detect` and `azure-blob-eventgrid-detect` have a captured
real-cloud deploy-and-first-event proof (2026-10-07, including a suppressed
redelivery); `gcp-gcs-pubsub-detect` does not yet. Status and evidence links
are in [DEPLOYMENT_VERIFICATION.md](DEPLOYMENT_VERIFICATION.md); the GCP proof
is tracked in [`#198`](https://github.com/msaad00/cloud-ai-security-skills/issues/198).

What is now committed:

- exact first-event walkthrough skeletons in each runner README
- the deploy/apply inputs that need to be bound
- the evidence operators should capture on the first successful run
- a CI-driven end-to-end harness ([`scripts/runner_e2e.sh`](../scripts/runner_e2e.sh))
  that exercises each runner against an ephemeral local backend (`moto` for
  AWS; in-process fakes of the GCS / Pub/Sub / Firestore and Blob / Service
  Bus / Table Storage SDK clients for GCP and Azure), runs a real ingest +
  detect skill pair, asserts sink arrival and redelivery dedupe, and regenerates
  [`docs/RUNTIME_PROFILES.md`](../docs/RUNTIME_PROFILES.md) on every run
  ([`.github/workflows/runner-e2e.yml`](../.github/workflows/runner-e2e.yml))

What is still not claimed:

- a checked-in record that the GCP walkthrough was executed against real
  deployed resources (the local harness proves handler wiring and dedupe, not
  IAM, trigger delivery, packaging, or quotas in a real cloud)
