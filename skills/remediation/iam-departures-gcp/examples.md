# Examples — IAM Departures GCP Remediation

## Quick start: deploy with Terraform

```bash
cd skills/remediation/iam-departures-gcp/infra/terraform
cp terraform.tfvars.example terraform.tfvars  # edit with your values

terraform init
terraform plan
terraform apply
```

The plan creates:

- Two CMEK-encrypted GCS buckets (`<prefix>-manifest`, `<prefix>-audit`).
- One Cloud KMS key ring + key (`iam-departures-gcp/iam-audit`).
- One Firestore (Native mode) database ID `iam-departures-gcp` + collection.
- Two Cloud Functions Gen 2 (parser + worker, Python 3.11).
- One Cloud Workflow `iam-departures-gcp-pipeline`.
- One Eventarc trigger on `google.cloud.storage.object.v1.finalized` for the manifest bucket prefix `departures/`.
- Two Pub/Sub topics (`iam-departures-gcp-dlq`, `iam-departures-gcp-alerts`).
- Four service accounts with IAM Conditions pinning destructive permissions to your org/folder.

## Run the parser locally against a sample manifest (dry run)

```bash
python skills/remediation/iam-departures-gcp/src/cloud_function_parser/handler.py \
  --dry-run skills/remediation/iam-departures-gcp/examples/manifest.json
```

The parser prints validation decisions for each entry: `remediate` /
`skip(reason=...)` / `error`. Nothing is written; no GCP API calls fire.

## Run the worker locally against a single validated entry (dry run)

```bash
export IAM_DEPARTURES_GCP_INCIDENT_ID=INC-2026-04-20-007
export IAM_DEPARTURES_GCP_APPROVER=alice@security
python skills/remediation/iam-departures-gcp/src/cloud_function_worker/handler.py \
  --dry-run skills/remediation/iam-departures-gcp/examples/manifest.json
```

Worker emits the 11-step plan per entry, marks each step `dry_run`, and writes
no audit row.

## Apply (real teardown — requires HITL env vars)

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/worker-sa.json
export IAM_DEPARTURES_GCP_INCIDENT_ID=INC-2026-04-20-007
export IAM_DEPARTURES_GCP_APPROVER=alice@security
export IAM_DEPARTURES_GCP_AUDIT_FIRESTORE_COLLECTION=iam-departures-gcp-audit
export IAM_DEPARTURES_GCP_AUDIT_BUCKET=acme-iam-departures-gcp-audit
export IAM_DEPARTURES_GCP_KMS_KEY=projects/acme-sec/locations/us/keyRings/iam-departures-gcp/cryptoKeys/iam-audit

python skills/remediation/iam-departures-gcp/src/cloud_function_worker/handler.py \
  --apply skills/remediation/iam-departures-gcp/examples/manifest.json
```

If either env var is missing, the worker refuses with `missing-hitl-env-vars`
before any GCP API call.

## Test trigger via GCS upload

The deployed pipeline is end-to-end driven by Eventarc. Drop the manifest into
the manifest bucket and the Workflow fires:

```bash
gsutil cp examples/manifest.json gs://acme-iam-departures-gcp-manifest/departures/2026-04-20.json
```

Watch the Workflow execution:

```bash
gcloud workflows executions list iam-departures-gcp-pipeline --location=us-central1
```

## Query audit records

```bash
# Firestore — operational dashboard
gcloud firestore documents list \
  --collection-group=iam-departures-gcp-audit \
  --filter='remediated_at > "2026-04-01"'

# BigQuery (after ingest-back)
bq query --use_legacy_sql=false '
SELECT
  iam_principal,
  account_id,
  remediation_actions,
  remediated_at,
  invoked_by,
  approved_by,
  approval_ticket,
  workflow_execution_id
FROM `acme-sec.security.iam_remediation_audit_gcp`
WHERE remediated_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
ORDER BY remediated_at DESC'
```

## Re-verify (drift detection)

```bash
python skills/remediation/iam-departures-gcp/src/cloud_function_worker/handler.py \
  --reverify skills/remediation/iam-departures-gcp/examples/manifest.json
```

The verifier re-reads target principal state and emits one of `verified` /
`drift` / `unreachable` per remediated entry. On `drift`, an OCSF Detection
Finding (class 2004) is emitted via the shared
[`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py)
contract so downstream SIEM picks it up as a fresh finding.
