# Case study: GCP event delivery and replay suppression

A reference pipeline needs to survive the platform's deployment and delivery
behavior as well as pass local handler tests. The GCP runner's recorded
2026-10-07 deployment exercised GCS → ingest function → Pub/Sub → detector →
findings topic, with Firestore holding deduplication state.

This is a summary of the [recorded deployment evidence](../runners/gcp-gcs-pubsub-detect/README.md#live-deploy-verification-status).
It used a synthetic firewall-event fixture in a real GCP project. The resources
were removed after the run. It is not a currently hosted demo.

## Design choices

| Choice | Reason | Operational cost |
|---|---|---|
| Reuse the ingestion and detection entrypoints | Keep local and cloud rule logic together | Package the repository layout and Python dependencies correctly |
| Separate ingestion and detection with Pub/Sub | Let delivery and retries operate at each stage | Configure topic permissions and monitor failures |
| Keep deduplication state in Firestore | Suppress repeated findings when an event is redelivered | Manage state lifetime and understand expiry behavior |
| Use explicit build and trigger identities | Make deployment and invocation permissions inspectable | Verify platform-specific role bindings and propagation |

## What the live run exposed

The deployment found gaps that local handler tests had not covered:

- The build service account needed access to fetch the packaged source.
- Eventarc trigger identities and Cloud Storage publication needed explicit
  bindings. Initial trigger deliveries returned `403` while a grant propagated.
- The function archive needed `requirements.txt`, and the source binding needed
  `GOOGLE_FUNCTION_SOURCE` for the existing handler filenames.
- Isolated deployment and teardown needed configurable resource prefixes and a
  configurable Firestore database.

The fixes and their context are recorded in
[PR #729](https://github.com/msaad00/cloud-ai-security-skills/pull/729).
This illustrates why a local SDK fake cannot establish that cloud packaging,
identity bindings, and delivery are correct.

## What was verified

The recorded run deployed 21 Terraform resources. After the trigger retry
succeeded, the findings subscription received one message whose body matched
the golden finding. Firestore held one deduplication document. Re-uploading
the same event produced no second finding in the observed run and preserved
the original deduplication entry.

The [evidence table](../runners/gcp-gcs-pubsub-detect/README.md#live-deploy-verification-status)
contains timestamps, invocation durations, artifact sizes, and the finding
hash. The [runner tests](../tests/integration/test_gcp_runner_template.py) cover the local
implementation. These are complementary checks.

## Limits and next verification

One successful deployment and redelivery test do not establish exactly-once
delivery under every failure, long-term availability, production detection
accuracy, or sustained throughput. A deployment in another environment needs
its own checks for permissions, retry behavior, deduplication expiry, backlog,
and downstream publication failures.

To reproduce the deployment, use the runner's
[prepared walkthrough](../runners/gcp-gcs-pubsub-detect/README.md#prepared-walkthrough)
and review its infrastructure and permissions first. For a credential-free
introduction to the skill contracts, start with the
[local CloudTrail investigation](WALKTHROUGH.md).
