# Skills Catalog

Skills are grouped by **what kind of work they do**, not which cloud they run in. An agent (or a human) picks a category based on the job at hand, then picks the skill inside that category by trigger phrase.

| Category | Question it answers | Output shape |
|---|---|---|
| [`compliance-cis-mitre/`](compliance-cis-mitre/) | "Is this config aligned with a published benchmark?" | Pass/fail per control, JSON + console |
| [`remediation/`](remediation/) | "Something is wrong — go fix it, gated and audited." | Audit row (DynamoDB + S3) + closed-loop verification |
| [`detection-engineering/`](detection-engineering/) | "What does an attack look like on this surface?" | **OCSF Detection Finding (class 2004)** + MITRE ATT&CK |
| [`ai-infra-security/`](ai-infra-security/) | "AI-native surfaces: models, agents, GPU, topology." | Config audit, graph overlay, runtime checks |

Every skill in every category is a **closed loop** (detect → act → audit → re-verify) and follows the [Anthropic skills spec](https://platform.claude.com/docs/en/build-with-claude/skills-guide): `SKILL.md` at the skill root with `name`, `description`, `license`, and a `Do NOT use…` clause in the description so agents route correctly.

## compliance-cis-mitre/

Read-only posture assessments mapped to published benchmarks (CIS, NIST CSF, MITRE ATT&CK).

| Skill | Scope | Checks |
|---|---|---:|
| [`cspm-aws-cis-benchmark`](compliance-cis-mitre/cspm-aws-cis-benchmark/) | AWS | 18 |
| [`cspm-gcp-cis-benchmark`](compliance-cis-mitre/cspm-gcp-cis-benchmark/) | GCP | 7 |
| [`cspm-azure-cis-benchmark`](compliance-cis-mitre/cspm-azure-cis-benchmark/) | Azure | 6 |
| [`k8s-security-benchmark`](compliance-cis-mitre/k8s-security-benchmark/) | Kubernetes | 10 |
| [`container-security`](compliance-cis-mitre/container-security/) | Any container runtime | 8 |

## remediation/

Active fix workflows — gated by grace periods, deny lists, protected-package lists, and idempotency checks.

| Skill | Scope |
|---|---|
| [`iam-departures-remediation`](remediation/iam-departures-remediation/) | Multi-cloud (AWS, Azure Entra, GCP, Snowflake, Databricks) IAM cleanup for departed employees |

## detection-engineering/ 🆕

Detection rules, threat hunts, and runtime monitors for AI infrastructure (MCP, agents, models) and traditional cloud surfaces. Every skill speaks the **OCSF 1.8 wire format** (current stable — `Detection Finding` class 2004, not the deprecated `Security Finding` 2001) so ingestion, detection, and analytics compose via Unix-style pipes.

See [`detection-engineering/README.md`](detection-engineering/README.md) for the full category contract and [`detection-engineering/OCSF_CONTRACT.md`](detection-engineering/OCSF_CONTRACT.md) for field-level pinning.

## ai-infra-security/

AI-native surfaces — model serving hardening, GPU tenant isolation, environment topology with MITRE ATT&CK/ATLAS overlays.

| Skill | Scope | Checks |
|---|---|---:|
| [`model-serving-security`](ai-infra-security/model-serving-security/) | Any ML serving stack | 16 |
| [`gpu-cluster-security`](ai-infra-security/gpu-cluster-security/) | Any GPU cluster | 13 |
| [`discover-environment`](ai-infra-security/discover-environment/) | Multi-cloud | n/a (graph) |

## How to add a new skill

1. Pick the category that matches the job (not the cloud).
2. Copy the nearest sibling as a starting point *or*, for detection-engineering, copy `detection-engineering/.templates/skill-template/` (coming in a follow-up PR).
3. Write `SKILL.md` with the spec-compliant frontmatter. Name must be ≤64 chars, `^[a-z0-9-]+$`, non-reserved.
4. In the `description`, lead with "Use when…" and close with "Do NOT use…" — that is the Anthropic pattern.
5. Add tests. If this is a detection-engineering skill, test against the frozen golden fixture in `detection-engineering/golden/`.
6. Register the test job in `.github/workflows/ci.yml`.
