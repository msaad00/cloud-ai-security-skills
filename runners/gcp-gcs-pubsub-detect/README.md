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
  Example: `python skills/ingestion/ingest-gcp-audit-ocsf/src/ingest.py`
- `DETECT_TOPIC`
  Fully qualified Pub/Sub topic path such as
  `projects/my-project/topics/cloud-security-detect`

### Detect function

- `DETECT_SKILL_CMD`
  Example: `python skills/detection/detect-gcp-open-firewall/src/detect.py`
- `DEDUPE_COLLECTION`
  Firestore collection used for replay-safe dedupe keys
- `DEDUPE_DATABASE`
  Optional Firestore database ID. Defaults to `(default)`; the Terraform
  template sets it from `firestore_database`.
- `DEDUPE_TTL_DAYS`
  Optional retention window for dedupe documents. Defaults to `30`. The
  Terraform template also enables Firestore TTL on the `expires_at` field so
  expired rows age out automatically.
- `FINDINGS_TOPIC`
  Fully qualified Pub/Sub topic path such as
  `projects/my-project/topics/cloud-security-findings`

## Packaging model

The Terraform template expects:
- an existing source bucket name
- one GCS bucket for Cloud Function source archives
- one object name for the ingest function archive
- one object name for the detect function archive
- an explicit `max_instance_count` ceiling (defaults to `50`)

That keeps the template deployable without assuming a build system.

Each archive carries its handler file, this directory's `requirements.txt`
(Functions Framework plus the Storage, Pub/Sub, and Firestore clients), and
the repo-relative `skills/_shared` and skill directories. The template sets
`GOOGLE_FUNCTION_SOURCE` so the handler file does not have to be renamed to
`main.py`.

Signature binding (verified on the 2026-10-07 live run): no decorator or
entry-point shim is needed. The platform built both functions with
`_GOOGLE_FUNCTION_SIGNATURE_TYPE=event`, so the Functions Framework calls the
entry points with the legacy `(data, context)` shape — the storage object
dict for ingest and the Pub/Sub message dict for detect. The handlers also
accept a single CloudEvent (payload on `.data`, Pub/Sub message under
`data.message`) in case a deployment uses the `cloudevent` signature.

The template also creates a dedicated build service account
(`roles/cloudbuild.builds.builder` plus read on the archive bucket) because
new projects build functions as the default compute account, which may hold
no roles. It grants each function's own service account
`roles/eventarc.eventReceiver` and `roles/run.invoker` as the trigger
identity, and grants the Cloud Storage service agent `roles/pubsub.publisher`
for the Eventarc storage trigger.

Optional naming inputs: `name_prefix` (topics and functions),
`service_account_prefix` (5-23 characters), `labels`, `firestore_database`,
and `firestore_deletion_policy` (`ABANDON` by default; `DELETE` lets
`terraform destroy` remove a named test database).

## Concurrency ceiling

The template exposes `max_instance_count` and defaults it to `50` for both the
ingest and detect Cloud Functions. Operators should lower or raise that ceiling
based on cost, quota, and downstream sink pressure for their environment.

## Security model

- no shell invocation; skill commands are tokenized with `shlex.split`
- `subprocess.run(..., shell=False)` only
- Firestore `create()` semantics prevent duplicate publish on replay
- dedupe rows carry `expires_at`; the template enables Firestore TTL so replay
  protection stays bounded instead of growing forever
- detect-side downstream publish keeps Pub/Sub futures outstanding until the
  batch is queued, so the client library can batch them before the handler
  waits for publish completion
- Pub/Sub findings fan-out sees only deduped findings
- operators should scope the service accounts to the specific bucket, topics,
  and Firestore collection for their environment

## Live Deploy Verification Status

Real deploy proof captured on 2026-10-07 (GCP `us-central1`, Cloud Functions
2nd gen `python311`, run image `python311_20260906_3_11_16_RC00`, builder
`python_20260926_RC00`) with `ingest-gcp-audit-ocsf` → `detect-gcp-open-firewall`
and the golden fixture `skills/detection-engineering/golden/gcp_open_firewall_raw.json`,
following the [Prepared Walkthrough](#prepared-walkthrough) below. All
resources were removed afterwards (`terraform destroy`, the two buckets, the
`gcf-v2-sources-*` bucket, the `gcf-artifacts` repository) and the APIs
enabled for the run were disabled again. Project ID is redacted.

| Step | Evidence |
|---|---|
| package | ingest zip 36,004 B, detect zip 38,905 B (handler + `requirements.txt` at root, `skills/_shared`, one skill dir) |
| deploy | `terraform apply` → 21 resources, including a named Firestore database with TTL on `expires_at`; both functions `ACTIVE`, built by the dedicated build service account |
| trigger | object `incoming/run1/gcp_open_firewall_raw.json` uploaded 05:44:15Z; the first five Eventarc deliveries got `403` while the `run.invoker` grant propagated (created ~1 min earlier), the retry at 05:45:45Z returned `200` (1.88 s) |
| ingest → topic | detect function invoked from the detect topic at 05:45:50Z, `200` (1.03 s); bare `python` resolves on the `python311` runtime |
| dedupe | Firestore document `gfw-8f8fe79c95260b06`, `payload_sha256=ce757899…141d` (byte-identical to the golden `gcp_open_firewall_pipe_findings.ocsf.jsonl` line, MITRE T1190), `expires_at` = seen_at + 30 d |
| publish | a subscription on the findings topic received exactly one message (published 05:45:51Z), body sha256 identical to the golden line |
| redelivery | same object re-uploaded as `incoming/run2-redeliver/…` 05:46:41Z → ingest `200` (1.46 s), detect `200` (0.51 s); Firestore still holds exactly 1 document with the original `seen_at`; no second message reached the findings topic |

Bugs the live run found and this repo now fixes:

- The first apply failed because the build ran as the project's default
  compute service account, which had no roles, so the source fetch step was
  denied. The template now creates a dedicated build service account.
- The template set no Eventarc trigger identity (it would default to the
  compute account without `run.invoker`) and did not grant the Cloud Storage
  service agent `roles/pubsub.publisher`; both are now in the template.
- No `requirements.txt` shipped, so the handlers' Pub/Sub, Storage, and
  Firestore imports would fall back to `None` and every invocation would raise.
- Topic, function, and service account names were hardcoded, and the
  `(default)` Firestore database is abandoned on destroy. The new naming
  inputs and `firestore_database` / `firestore_deletion_policy` (with the
  matching `DEDUPE_DATABASE` handler setting) allow an isolated, fully
  removable deployment.

Operational notes from the live run:

- Right after enabling Eventarc, function creation can fail with "Permission
  denied while using the Eventarc Service Agent"; re-apply after a few
  minutes.
- Expect `403` deliveries for about a minute after apply while the trigger's
  `run.invoker` grant propagates; Eventarc retries them.
- The Firestore TTL field takes about 6 minutes to create and to delete.
- Cloud Functions creates a `gcf-v2-sources-<project-number>-<region>` bucket
  and a `gcf-artifacts` Artifact Registry repository outside Terraform; delete
  them separately when tearing down.

## First Event Proof Checklist

When capturing the live walkthrough for this runner, record:

1. the exact Terraform apply inputs and deployed resources
2. the packaged Cloud Function artifacts and runtime binding
3. one object finalized in the watched GCS bucket
4. evidence that:
   - ingest function ran
   - the detect Pub/Sub topic received messages
   - detect function ran
   - a Firestore dedupe document was created
   - findings topic publish succeeded

## Prepared Walkthrough

### 0. Package the handlers

From the repo root (one archive per function; the repo layout must be
preserved because skills resolve `skills._shared` relative to their own path):

```bash
zip -qr -X /tmp/ingest.zip skills/_shared skills/ingestion/ingest-gcp-audit-ocsf/src -x '*__pycache__*'
zip -qr -X /tmp/detect.zip skills/_shared skills/detection/detect-gcp-open-firewall/src -x '*__pycache__*'
(cd runners/gcp-gcs-pubsub-detect && zip -q -X /tmp/ingest.zip requirements.txt && zip -q -X /tmp/detect.zip requirements.txt \
  && cd src && zip -q -X /tmp/ingest.zip ingest_handler.py && zip -q -X /tmp/detect.zip detect_handler.py)
gcloud storage cp /tmp/ingest.zip gs://<function-archive-bucket>/code/ingest.zip
gcloud storage cp /tmp/detect.zip gs://<function-archive-bucket>/code/detect.zip
```

### 1. Deploy the infrastructure

The ingest skill must emit OCSF (its default): `detect-*` skills consume OCSF
and skip native-format records, so `--output-format native` on the ingest side
produces zero findings.

```bash
terraform -chdir=runners/gcp-gcs-pubsub-detect init
terraform -chdir=runners/gcp-gcs-pubsub-detect apply \
  -var project_id=<gcp-project-id> \
  -var region=<gcp-region> \
  -var source_bucket_name=<existing-source-bucket> \
  -var function_source_bucket=<function-archive-bucket> \
  -var ingest_source_object=code/ingest.zip \
  -var detect_source_object=code/detect.zip \
  -var 'ingest_skill_command=python skills/ingestion/ingest-gcp-audit-ocsf/src/ingest.py' \
  -var 'detect_skill_command=python skills/detection/detect-gcp-open-firewall/src/detect.py'
```

### 2. Bind the function archives

- confirm both functions are `ACTIVE` and point at the intended skill
  commands: `gcloud functions describe <name-prefix>-ingest --region <gcp-region>`

### 3. Send one real event

```bash
gcloud storage cp skills/detection-engineering/golden/gcp_open_firewall_raw.json \
  gs://<existing-source-bucket>/incoming/gcp_open_firewall_raw.json
```

### 4. Capture proof

- Cloud Logging request entries for the ingest function (`200`)
- Cloud Logging request entries for the detect function (`200`)
- a Firestore dedupe document with `payload_sha256` and `expires_at`
- a message on the findings topic (create a subscription before the upload)
