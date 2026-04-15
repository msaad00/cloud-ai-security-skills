# gcp-gcs-pubsub-detect

Reference persistent runner template for continuous ingest -> detect pipelines
on GCP.

## What it does

```text
GCS object finalized
  -> ingest Cloud Function
  -> Pub/Sub detect topic
  -> detect Cloud Function
  -> Firestore dedupe
  -> Pub/Sub findings topic
```

The runner keeps state and side effects at the edges:
- Cloud Storage is the raw object source
- Pub/Sub provides durable decoupling and downstream fan-out
- Firestore stores replay-safe dedupe keys
- the skills remain unchanged and stateless

## When to use it

- You want a repo-owned GCP pattern that mirrors the shipped AWS runner
- You need continuous ingest -> detect on GCP without changing skill code
- You want a queue-driven example that can wrap any compatible `ingest-*` and
  `detect-*` pair

## What it does not do

- It is not a generic sink framework for every GCP destination
- It does not package Cloud Function archives for you
- It does not hardcode a specific skill family, detector, or downstream sink

## Required environment variables

### Ingest function

- `INGEST_SKILL_CMD`
  Example: `python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py --output-format native`
- `DETECT_TOPIC`
  Fully qualified Pub/Sub topic path such as
  `projects/my-project/topics/cloud-security-detect`

### Detect function

- `DETECT_SKILL_CMD`
  Example: `python skills/detection/detect-lateral-movement/src/detect.py --output-format native`
- `DEDUPE_COLLECTION`
  Firestore collection used for replay-safe dedupe keys
- `FINDINGS_TOPIC`
  Fully qualified Pub/Sub topic path such as
  `projects/my-project/topics/cloud-security-findings`

## Packaging model

The Terraform template expects:
- an existing source bucket name
- one GCS bucket for Cloud Function source archives
- one object name for the ingest function archive
- one object name for the detect function archive

That keeps the template deployable without assuming a build system.

## Security model

- no shell invocation; skill commands are tokenized with `shlex.split`
- `subprocess.run(..., shell=False)` only
- Firestore `create()` semantics prevent duplicate publish on replay
- Pub/Sub findings fan-out sees only deduped findings
- operators should scope the service accounts to the specific bucket, topics,
  and Firestore collection for their environment
