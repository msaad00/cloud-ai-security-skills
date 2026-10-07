<!-- AUTO-GENERATED — do not hand-edit. Source: runtime-profile-results.jsonl, regenerator: scripts/build_runtime_profiles_doc.py. -->

# Runtime Profiles — Runner Templates

This document is regenerated from `runtime-profile-results.jsonl` every time the harness runs. It is intentionally light on prose: the point is to detect **regressions** between CI runs, not to advertise raw numbers.

Related issues:
- [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) — deploy and verify all three runner templates end to end. This doc covers the local CI surface only; real-cloud deploy proof is still outstanding (see `runners/DEPLOYMENT_VERIFICATION.md`).
- [#199](https://github.com/msaad00/cloud-ai-security-skills/issues/199) — benchmark runtime profiles at representative scale (CI cadence).

## What this is

Every record below comes from `scripts/runner_e2e.sh`, which spins each runner template up against an ephemeral local backend, sends **N synthetic events matched to that runner's real contract**, and asserts both **audit-log capture** and **sink arrival** before reporting timings.

Sample size defaults to **N = 20** per scenario. These are CI-runner numbers on a free-tier executor. Do **not** quote these p50/p95s as customer-scale numbers — they exist to flag a regression, not to advertise throughput.

## Measured runs

| Runner | Scenario | Samples | p50 | p95 | Mean | Sink arrival | Audit chain | Captured |
|---|---|---:|---:|---:|---:|---:|:---:|---|
| `cloud-runner-aws-s3-sqs` | `s3-eventbridge-ingest` | 20 | 89.38 ms | 110.17 ms | 94.32 ms | 20 | n/a | 2026-10-07T01:01:46Z |
| `cloud-runner-azure-blob-eventgrid` | `blob-eventgrid-ingest-detect-dedupe` | 20 | 192.50 ms | 382.14 ms | 224.41 ms | 1 | n/a | 2026-10-07T01:01:55Z |
| `cloud-runner-gcp-gcs-pubsub` | `gcs-finalize-ingest-detect-dedupe` | 20 | 187.09 ms | 229.42 ms | 192.38 ms | 1 | n/a | 2026-10-07T01:01:50Z |
| `mcp-sse` | `jsonrpc-ping-and-tools-list` | 20 | 135.92 ms | 285.95 ms | 140.30 ms | 20 | yes | 2026-10-07T01:01:44Z |
| `webhook-receiver` | `ingest-cloudtrail-ocsf` | 20 | 413.43 ms | 505.10 ms | 426.28 ms | 0 | n/a | 2026-10-07T01:01:40Z |

### Per-scenario assertions

Each `ok` record above means **all** of the following held for the run:

- the runner accepted every one of the N requests with no failures;
- the audit assertion for that runner passed (the receiver writes a single-line JSONL audit; the SSE runner writes an HMAC-chained log and `scripts/verify_audit_chain.py` returned exit 0; the AWS, GCP, and Azure runners have no in-process audit chain — their audit gaps are documented below);
- the **sink-arrival assertion** for that runner held (webhook receiver currently does not fan out — gap below; SSE response payload shape was verified for every reply; AWS scenario asserts exact SQS message count = N; GCP and Azure scenarios assert the findings topic received exactly the golden findings once and that the N-1 redeliveries were suppressed by the dedupe store).

## Honest gaps

Scenarios in this section have **no automated coverage in this PR**. The doc lists them so readers can see the coverage boundary without having to grep the harness source.

_None._

### Sub-gaps inside ok-status scenarios

Even `ok` scenarios have bounded coverage — the harness records the boundary on each row's `audit_chain_status` and `sink_status` so this doc never claims more than was tested.

- `cloud-runner-aws-s3-sqs` / `s3-eventbridge-ingest` — audit_chain_status: `gap_aws_runner_audit_writes_via_cloudwatch_only`
- `cloud-runner-azure-blob-eventgrid` / `blob-eventgrid-ingest-detect-dedupe` — audit_chain_status: `gap_azure_runner_audit_via_platform_logging_only`
- `cloud-runner-gcp-gcs-pubsub` / `gcs-finalize-ingest-detect-dedupe` — audit_chain_status: `gap_gcp_runner_audit_via_cloud_logging_only`
- `webhook-receiver` / `ingest-cloudtrail-ocsf` — sink_status: `gap_sink_fanout_needs_per_sink_flags`

## How to run

Locally:

```bash
uv sync --group dev --group webhook --group mcp-sse --group http-runtime
bash scripts/runner_e2e.sh
python scripts/build_runtime_profiles_doc.py
```

In CI the workflow `.github/workflows/runner-e2e.yml` runs the harness on every PR that touches `runners/**`, `mcp-server/**`, `skills/_shared/**`, the harness itself, or the workflow file, plus once a day at 02:00 UTC. The workflow also runs `build_runtime_profiles_doc.py --check` so a PR that updates the harness but not the doc fails immediately.

## Tooling notes

- `helm lint` / `docker build` for the runner templates run in `.github/workflows/runner-templates.yml`, not this harness. The harness assumes the templates render — it does not re-validate them.
- Backends are local only: the AWS runner runs against `moto`; the GCP and Azure runners run their real handlers against in-process fakes of the cloud SDK clients (GCS, Pub/Sub, Firestore; Blob Storage, Service Bus, Table Storage), not emulators and not a real cloud. IAM, trigger wiring, packaging, and quotas are not exercised here — the real-cloud deploy proof requested by #198 stays the responsibility of an operator running the templates against a real account.

