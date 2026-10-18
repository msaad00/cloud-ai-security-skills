# Why this repo exists

Security engineers and agent developers need reusable ways to turn provider
logs into findings they can inspect and reproduce. This repo supplies small
Python skills with documented inputs, output contracts, tests, and official
references. Start with the [CloudTrail walkthrough](WALKTHROUGH.md): one local
pipeline produces a finding and shows what evidence supports it.

## What you can reuse

| Need | Shipped implementation | Boundary |
|---|---|---|
| Normalize provider logs | Ingestion skills and the [OCSF contract](../skills/detection-engineering/OCSF_CONTRACT.md) | Support is specific to each skill's documented input shapes |
| Explain a rule match | Deterministic detectors, source context, and ATT&CK mappings | A matching event does not by itself prove malicious intent |
| Export findings | SARIF and Mermaid converters | Local conversion does not verify hosted ingestion or rendering |
| Expose tools to an agent | Local MCP wrapper with argument policy, allowlists, execution limits, and audit support | Controls depend on the runtime and operator configuration |
| Plan a response | Dry-run remediation with per-skill approval and scope contracts | MCP rejects write-capable `--apply`; approved writes use documented CLI or provider workflows |
| Process events continuously | Reference cloud runners and storage adapters | Operators deploy and configure credentials, queues, deduplication, and monitoring |

The [runtime boundary table](ARCHITECTURE.md#runtime-boundaries) explains
which controls apply to each surface. Sharing a skill entrypoint does not make
CLI, MCP, library, webhook, and cloud execution equivalent.

## Why use maintained skills

A team can build these pipelines itself, with or without AI assistance. The
benefit here is reusable implementation and review evidence: input validation,
provider mappings, regression fixtures, and documented failure behavior are
available together. Changes can be checked against the same contracts used by
downstream consumers.

Those contracts still need review. Passing a schema validator does not establish
that a framework mapping is semantically correct. A synthetic test does not
measure alert quality on your organization's traffic. A sandbox option does not
mean every runtime activates that sandbox. Inspect the skill and the execution
surface you intend to use.

## What the evidence supports

- **Fixture behavior:** [golden fixtures](../skills/detection-engineering/golden/README.md)
  exercise documented inputs and expected outputs. They are synthetic.
- **Scoring:** the [scoring manifest](../skills/detection-engineering/scoring/corpus.yaml)
  currently has three detector entries, all synthetic. Its precision and recall
  results describe those labelled cases, not production threat detection.
- **Deployment:** the [GCP runner case study](GCP_RUNNER_CASE_STUDY.md) records
  one live deployment using a synthetic event fixture, including replay
  suppression. It does not establish sustained throughput or customer adoption.
- **Security boundaries:** [SECURITY.md](../SECURITY.md), the
  [MCP audit contract](MCP_AUDIT_CONTRACT.md), and [HITL policy](HITL_POLICY.md)
  describe controls and requirements. Operators must configure and verify them
  for their environment.

No production accuracy or engineering-hours-saved estimate follows from the
catalog size. Evaluate a small workflow against your own requirements first.

## When to choose something else

If an existing SIEM already covers the workflow, assess the value of another
pipeline before adding it. If you need a hosted service, managed operations,
or broad behavioral detection, this repository alone does not provide them.
For a one-off analysis, a reviewed script may be enough.

Use this repo when its documented skill contracts and reusable execution paths
fit your workflow. Begin with [the demo](QUICKSTART.md), check the
[coverage catalog](SKILL_INDEX.md), and verify the evidence for the specific
skills you plan to adopt.
