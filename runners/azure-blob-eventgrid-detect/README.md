# azure-blob-eventgrid-detect

Reference persistent runner template for Azure Blob Storage event-driven ingest
and detection pipelines.

## Flow

```text
Blob create
  -> Event Grid subscription
  -> ingest queue
  -> ingest handler
  -> detect queue
  -> detect handler
  -> Table Storage dedupe
  -> Service Bus topic
```

The runner keeps state and side effects at the edges:
- Blob Storage is the raw source
- Event Grid routes blob-created events into the ingest queue
- the ingest handler reads the blob, runs an ingest skill, and enqueues lines
- the detect handler consumes queue messages, runs a detect skill, dedupes on a
  stable UID, and publishes new findings to a topic

The skills remain unchanged and stateless.

## When to use it

- You want a repo-owned Azure persistent runner example beyond IAM departures
- You need a minimal Azure pattern for continuous ingest -> detect with replay
  safety
- You want to wire any compatible `ingest-*` and `detect-*` skill pair into a
  queue-driven loop

## What it does not do

- It is not a generic sink framework for every cloud or SIEM
- It does not package Azure Function App artifacts for you
- It does not hardcode a specific skill family, sink vendor, or storage format

## Required environment variables

### Ingest handler

- `INGEST_SKILL_CMD`
  Example: `python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py --output-format native`
- `DETECT_QUEUE_NAME`
- `SERVICE_BUS_FQDN`

### Detect handler

- `DETECT_SKILL_CMD`
  Example: `python skills/detection/detect-lateral-movement/src/detect.py --output-format native`
- `DETECT_QUEUE_NAME`
- `ALERT_TOPIC_NAME`
- `DEDUPE_TABLE_NAME`
- `TABLE_ACCOUNT_URL`
- `SERVICE_BUS_FQDN`

## Packaging model

The template expects the operator to package the queue handlers together with
their Python dependencies and bind them to an Azure runtime of their choice.
The template itself provisions:

- the Event Grid subscription for blob-created events
- an ingest queue
- a detect queue
- a fan-out topic
- a Table Storage account for replay-safe dedupe state

## Concurrency ceiling

The Bicep template exports `recommendedMaxInstances` and defaults it to `50`.
Because this runner intentionally does not provision the Function App or
Container Apps packaging layer, the ceiling is an operator-facing contract: wire
the same value into your chosen Azure runtime so queue-driven scale does not run
unbounded.

## Security model

- no shell invocation; skill commands are tokenized with `shlex.split`
- `subprocess.run(..., shell=False)` only
- Event Grid payloads are treated as untrusted input
- dedupe prevents duplicate publishes on replay
- operators should scope the Azure role assignments to the specific blob
  source, queue, topic, and table resources in their environment

## Live Deploy Verification Status

Current repo reality:

- the Bicep template is shipped
- handler behavior is covered in tests
- template validation runs in CI
- a checked-in real-cloud deploy-and-first-event walkthrough is still pending

That remaining deployment proof is tracked in
[`#198`](https://github.com/msaad00/cloud-ai-security-skills/issues/198).

## First Event Proof Checklist

When capturing the live walkthrough for this runner, record:

1. the exact Bicep deployment inputs and provisioned resources
2. the chosen Azure runtime packaging path for the handlers
3. one blob created in the watched source path
4. evidence that:
   - Event Grid routed the event
   - ingest queue received the message
   - ingest handler ran and enqueued detect work
   - detect handler ran
   - Table Storage dedupe wrote a stable UID row
   - Service Bus topic publish succeeded
