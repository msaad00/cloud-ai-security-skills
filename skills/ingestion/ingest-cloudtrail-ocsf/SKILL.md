---
name: ingest-cloudtrail-ocsf
description: >-
  Convert raw AWS CloudTrail events (JSON or NDJSON, single events or
  CloudTrail digest files) into OCSF 1.8 API Activity events (class 6003).
  Maps userIdentity to OCSF actor, sourceIPAddress to src_endpoint, eventName
  to api.operation, eventSource to api.service.name, and infers activity_id
  (Create / Read / Update / Delete) from the event verb. Sets status_id to
  Failure when CloudTrail records an errorCode. Use when the user mentions
  CloudTrail ingestion, AWS audit log normalization, OCSF pipeline for AWS,
  or feeding CloudTrail into a SIEM. Do NOT use for GCP audit logs (use
  ingest-gcp-audit-ocsf), Azure activity logs (use
  ingest-azure-activity-ocsf), or Kubernetes audit logs (use
  ingest-k8s-audit-ocsf). Do NOT use as a detection skill — this skill only
  normalises events, it does not flag anything.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: ocsf, native
---

# ingest-cloudtrail-ocsf

Thin, single-purpose ingestion skill: raw CloudTrail JSON in → canonical event projection → OCSF 1.8 API Activity JSONL or native enriched JSONL out. No detection logic, no side effects, no AWS API calls. Reads files or stdin; writes JSONL or stdout.

## Wire contract

Reads either of the two CloudTrail layouts that are emitted by the AWS service:

1. **Single event** — one JSON object per line (NDJSON, e.g. EventBridge → Kinesis Firehose to S3)
2. **CloudTrail digest** — top-level `{"Records": [...]}` wrapping an array of events (the format `aws s3 cp` retrieves directly from the CloudTrail bucket)

The skill auto-detects which shape it's looking at and unwraps `Records` if present.

By default it writes OCSF 1.8 **API Activity** (`class_uid: 6003`, `category_uid: 6`). See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) for the field-level pinning that every OCSF event matches.

When `--output-format native` is selected, it emits the same event in the repo's native enriched shape with stable `event_uid`, normalized provider/account/operation/status fields, and preserved actor/session/source context, but without the OCSF envelope fields.

## Native output format

`--output-format native` returns one JSON object per event with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "api_activity"`
- `event_uid`
- `provider`, `account_uid`, `region`
- `time_ms`
- `activity_id`, `activity_name`
- `status_id`, `status`, `status_detail`
- `actor`, `api`, `src`, `cloud`, and `resources`

The native shape keeps the same normalized semantics as the OCSF projection,
but omits `class_uid`, `category_uid`, `type_uid`, and `metadata.product`.

## activity_id inference

CloudTrail doesn't tell you whether an event is a Create / Read / Update / Delete — you have to infer from the verb in `eventName`. The skill uses a deterministic prefix table:

| `eventName` prefix | OCSF activity | id |
|---|---|---:|
| `Create*`, `Run*`, `Start*`, `Issue*` | Create | 1 |
| `Get*`, `List*`, `Describe*`, `View*`, `Lookup*`, `Search*`, `Head*`, `Read*` | Read | 2 |
| `Update*`, `Modify*`, `Put*`, `Set*`, `Edit*`, `Attach*`, `Associate*`, `Add*`, `Enable*` | Update | 3 |
| `Delete*`, `Remove*`, `Terminate*`, `Stop*`, `Detach*`, `Disable*`, `Disassociate*` | Delete | 4 |
| anything else | Other | 99 |

## status_id

CloudTrail records a top-level `errorCode` field when an API call fails. The skill sets:

- `status_id = 1` (Success) when `errorCode` is absent
- `status_id = 2` (Failure) when `errorCode` is present
- `status_detail` is populated with the `errorMessage` for fast triage

## Usage

```bash
# Single file
python src/ingest.py cloudtrail.json > cloudtrail.ocsf.jsonl

# Same input, native enriched output
python src/ingest.py cloudtrail.json --output-format native > cloudtrail.native.jsonl

# Piped from S3 sync
aws s3 cp s3://my-cloudtrail-bucket/AWSLogs/.../recent.json.gz - | gunzip | python src/ingest.py
```

## What's NOT mapped (yet)

CloudTrail carries fields the OCSF 1.8 API Activity class has homes for, but the
mapping is one-shot per skill. The first version focuses on the high-signal
fields any detection skill needs:

- `actor.user.name` (from `userIdentity.userName` or principal)
- `actor.session.uid` (from `userIdentity.accessKeyId`)
- `actor.session.created_time` (from `userIdentity.sessionContext.attributes.creationDate`)
- `src_endpoint.ip` and `src_endpoint.svc_name` (from `sourceIPAddress` and `userAgent`)
- `api.operation`, `api.service.name`, `api.request.uid` (from `eventName`, `eventSource`, `eventID`)
- `resources[]` (from `requestParameters` — only top-level keys, no recursion)
- `cloud.account.uid`, `cloud.region` (from `recipientAccountId`, `awsRegion`)
- `metadata.product.feature.name = "ingest-cloudtrail-ocsf"`

Fields **explicitly out of scope** for v0.1: `request.data` and `response.data` (often huge), `additionalEventData` (free-form), MFA context. Add these in a follow-up if a detector needs them.

## Tests

`tests/test_ingest.py` runs the ingester against [`../golden/cloudtrail_raw_sample.jsonl`](../golden/cloudtrail_raw_sample.jsonl) and asserts deep-equality against [`../golden/cloudtrail_sample.ocsf.jsonl`](../golden/cloudtrail_sample.ocsf.jsonl) with volatile fields scrubbed. Plus unit tests for the activity_id mapping table, status_id detection, and Records-wrapper auto-detection.
