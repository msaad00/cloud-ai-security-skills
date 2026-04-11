# cloud-security

[![CI](https://github.com/msaad00/cloud-security/actions/workflows/ci.yml/badge.svg)](https://github.com/msaad00/cloud-security/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![OCSF 1.8](https://img.shields.io/badge/OCSF-1.8-22d3ee)](https://schema.ocsf.io/1.8.0)
[![Scanned by agent-bom](https://img.shields.io/badge/scanned_by-agent--bom-164e63)](https://github.com/msaad00/agent-bom)

**OCSF-native detection engineering and posture for cloud and AI infrastructure.** Normalise every source to **OCSF 1.8** on the wire, then compose ingest → detect → view skills like Unix pipes. MITRE ATT&CK inside every finding. Read-only, agentless, least-privilege, closed-loop.

```bash
python skills/detection-engineering/ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python skills/detection-engineering/detect-privilege-escalation-k8s/src/detect.py \
  | python skills/detection-engineering/convert-ocsf-to-sarif/src/convert.py \
  > findings.sarif
```

## Layers

| Layer | Role | Output |
|---|---|---|
| **Ingest** | Per-source raw log → OCSF | API / Network / HTTP / Application Activity |
| **Detect** | OCSF → finding + MITRE ATT&CK | Detection Finding (class 2004) |
| **Evaluate** | OCSF → framework check | Compliance Finding (class 2003) — CIS / NIST / SOC 2 |
| **View** | OCSF → SARIF / Mermaid / graph | GitHub Security tab, PR comments, dashboards |
| **Remediate** | Finding → action (HITL-gated, audited) | Dual-write audit row |

Each skill is a standalone Python bundle following [Anthropic's skill spec](https://platform.claude.com/docs/en/build-with-claude/skills-guide) — `SKILL.md` with trigger phrases and a `Do NOT use…` clause, `src/`, `tests/`, golden fixtures, `REFERENCES.md`. Runs from the CLI, in CI, or via any agent that reads `SKILL.md` (Claude Desktop, Cursor, Codex, Cortex, Windsurf).

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full layered diagram and closed-loop vendor flow.

## Coverage

<details>
<summary><b>Skills shipped today</b></summary>

```
skills/
├── compliance-cis-mitre/           "Aligned with a published benchmark?"
│   ├── cspm-aws-cis-benchmark      (CIS AWS Foundations v3.0 — 18 checks)
│   ├── cspm-gcp-cis-benchmark      (CIS GCP Foundations v3.0 — 7 checks)
│   ├── cspm-azure-cis-benchmark    (CIS Azure Foundations v2.1 — 6 checks)
│   ├── k8s-security-benchmark      (CIS Kubernetes — 10 checks)
│   └── container-security          (CIS Docker — 8 checks)
│
├── remediation/                    "Fix it, gated and audited"
│   └── iam-departures-remediation  (event-driven, DLQ + SNS, dual audit)
│
├── detection-engineering/          "What does an attack look like on this surface?"
│   ├── ingest-cloudtrail-ocsf      AWS            → API Activity 6003
│   ├── ingest-gcp-audit-ocsf       GCP            → API Activity 6003
│   ├── ingest-azure-activity-ocsf  Azure          → API Activity 6003
│   ├── ingest-k8s-audit-ocsf       K8s            → API Activity 6003
│   ├── ingest-mcp-proxy-ocsf       MCP            → Application Activity 6002
│   ├── detect-mcp-tool-drift                      → T1195.001 Supply Chain
│   ├── detect-privilege-escalation-k8s            → T1552.007 / T1611 / T1098 / T1550.001
│   ├── detect-sensitive-secret-read-k8s           → T1552.007 Container API
│   ├── convert-ocsf-to-sarif                      → GitHub Security tab
│   └── convert-ocsf-to-mermaid-attack-flow        → PR comments
│
└── ai-infra-security/              "AI-native surfaces"
    ├── model-serving-security      (16 checks — auth / rate limit / egress / safety)
    ├── gpu-cluster-security        (13 checks — runtime / driver / tenant isolation)
    └── discover-environment        (MITRE ATT&CK + ATLAS graph overlay)
```

**Roadmap:** 14 open issues ([#26](https://github.com/msaad00/cloud-security/issues/26)–[#39](https://github.com/msaad00/cloud-security/issues/39)) covering VPC Flow / GuardDuty / Security Hub / AWS Config / Okta / GitHub / Workspace / Slack / Workday / Salesforce / SAP / GCP + Azure parity / folder reshape.

</details>

## Security & trust

This is a security tool. Trustworthiness is the first feature, not an afterthought. Eleven principles pinned in [`SECURITY_BAR.md`](SECURITY_BAR.md), every skill graded against every principle.

<details>
<summary><b>The eleven principles</b></summary>

| # | Principle | What it means |
|---|---|---|
| 1 | **Read-only by default** | Posture + detection NEVER call write APIs. Remediation isolates the write path behind explicit IAM grants and dry-run defaults. |
| 2 | **Agentless** | No daemons, no sidecars, no continuously running processes. Short-lived Python scripts that read what's already there. |
| 3 | **Least privilege** | Each skill documents the EXACT IAM / RBAC permissions it needs in `REFERENCES.md`. Minimal set only. |
| 4 | **Defense in depth** | Posture + detection + remediation + audit + re-verify all run in parallel and back each other up. |
| 5 | **Closed loop** | Every workflow has a verification step: detect → finding → action → audit → re-verify. Drift is itself a detection. |
| 6 | **OCSF on the wire** | All ingest + detect skills speak OCSF 1.8 JSONL. MITRE ATT&CK lives inside `finding_info.attacks[]`. |
| 7 | **Secure by design** | Security is a first-class input to the skill's architecture, not a bolt-on. |
| 8 | **Secure code** | Defensive parsing on every input boundary. No `eval`/`exec`/`pickle.loads` on untrusted data. Parameterised SQL only. `bandit` in CI. |
| 9 | **Secure secrets & tokens** | No hardcoded creds. Secrets from cloud secret stores. Short-lived tokens. Logs scrub creds. CI greps for `AKIA` / `sk-` / `ghp_` patterns. |
| 10 | **No telemetry** | No phone-home. Findings stay local unless the operator explicitly forwards them. |
| 11 | **HITL, no rogue behaviour** | A skill never escalates its own privileges, never bypasses guardrails, never invokes siblings it wasn't composed with. Destructive actions require HITL gates. |

</details>

<details>
<summary><b>How trust is verified</b></summary>

- **Golden-fixture tests** — every detection skill is tested against frozen OCSF inputs so a refactor that loses coverage fails CI
- **Wire-contract tests** — every ingest skill emits exactly the OCSF shape pinned in [`OCSF_CONTRACT.md`](skills/detection-engineering/OCSF_CONTRACT.md); cross-skill assertions verify every detect skill emits Detection Finding (2004) with MITRE ATT&CK v14
- **End-to-end integration tests** — `tests/integration/` pipes raw logs through the full ingest → detect → convert chain and deep-equals the frozen SARIF + Mermaid goldens
- **Static analysis** — `ruff check` + `ruff format --check` + `bandit` + hardcoded-secret grep on every PR
- **Per-skill `REFERENCES.md`** — every skill lists the official docs, schemas, and IAM policies it depends on. No opaque dependencies, no fabricated APIs
- **`agent-bom` scans** — `code` / `skills scan` / `fs` / `iac` run on every push; IaC findings land in the GitHub Security tab under `agent-bom-iac`

</details>

See [`SECURITY.md`](SECURITY.md) for the disclosure policy, [`SECURITY_BAR.md`](SECURITY_BAR.md) for the per-principle verification matrix, and [`ARCHITECTURE.md`](ARCHITECTURE.md) for the layered architecture.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). TL;DR — new skills copy the nearest sibling, add `SKILL.md` + `src/` + `tests/` + golden fixtures + `REFERENCES.md`, add a row to the `SECURITY_BAR.md` matrix, open a PR.

## License

[Apache 2.0](LICENSE)
