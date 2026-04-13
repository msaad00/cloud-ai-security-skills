# Cloud Security Skills Collection

This repository contains production-ready cloud security automations structured as
[Anthropic skills](https://docs.anthropic.com) for AI agents.

## Repository structure

Skills are grouped into layered categories — not by cloud. The category answers
*what kind of work does this skill do*, not *which cloud does it run in*. See
[`skills/README.md`](skills/README.md) for the full catalog.

```
skills/
├── ingestion/                     # raw source → OCSF 1.8
│   ├── ingest-cloudtrail-ocsf/
│   ├── ingest-gcp-audit-ocsf/
│   ├── ingest-azure-activity-ocsf/
│   ├── ingest-k8s-audit-ocsf/
│   └── ingest-mcp-proxy-ocsf/
│
├── detection/                     # OCSF → Detection Finding 2004 + MITRE
│   ├── detect-mcp-tool-drift/
│   ├── detect-privilege-escalation-k8s/
│   ├── detect-sensitive-secret-read-k8s/
│   └── detect-lateral-movement-aws/
│
├── evaluation/                    # posture, benchmark, and inventory checks
│   ├── cspm-aws-cis-benchmark/
│   ├── cspm-gcp-cis-benchmark/
│   ├── cspm-azure-cis-benchmark/
│   ├── k8s-security-benchmark/
│   ├── container-security/
│   ├── model-serving-security/
│   ├── gpu-cluster-security/
│   └── discover-environment/
│
├── view/                          # OCSF → rendered/review formats
│   ├── convert-ocsf-to-sarif/
│   └── convert-ocsf-to-mermaid-attack-flow/
│
├── remediation/                   # active fix workflows, gated and audited
│   └── iam-departures-remediation/
│
└── detection-engineering/         # temporary transition home
    ├── OCSF_CONTRACT.md
    └── golden/
```

Every skill in every category is a closed loop: **detect → act → audit → re-verify**.

The full layered architecture (Sources → Ingestion → OCSF → Detection / Evaluation → View → Remediation) is documented in [`ARCHITECTURE.md`](ARCHITECTURE.md). The eleven-principle security contract is in [`SECURITY_BAR.md`](SECURITY_BAR.md). Per-skill official references and IAM policies live in each skill's `REFERENCES.md`.
The CSPM skills are detection-only and re-verify the same `control_id` on the next run.
The remediation skills (IAM departures, vuln pipeline) write back to a dual audit
trail (DynamoDB + S3) and ingest results into the source warehouse so the next
reconciler run *cross-checks* the previous remediation actually landed.

## Agent guardrails — REQUIRED reading before invoking these skills

If you are an AI agent (Claude, Cursor, Codex, Cortex, Windsurf, etc.) loading
any skill from this repo, you must operate inside these guardrails. They are
enforced in code, infra, and IAM — not just documentation. Violating them
should be impossible for a least-privilege caller, but you should also refuse
to attempt them.

### 1. Read-only by default

- **CSPM skills (`cspm-aws/gcp/azure-cis-benchmark`)** are *read-only*. They use
  `roles/viewer`, `iam.securityReviewer`, and Azure `Reader`. They have **zero**
  write permissions to any cloud account. Never wrap them in code that mutates
  state — that would be outside the skill contract.
- **`iam-departures-remediation` reconciler** is read-only against HR sources
  and only *writes a manifest* to S3. The Step Function is the only thing that
  touches IAM.

### 2. Human-in-the-loop (HITL) for destructive actions

The IAM departures pipeline is the only destructive workflow. HITL is enforced
at three layers:

| Layer | Mechanism | Override |
|-------|-----------|----------|
| **Grace period** | 7-day default window before remediation runs (configurable per env) | HR can revert termination during the grace period and the manifest will reflect it |
| **Deny policies** | Explicit IAM `Deny` on `root`, `break-glass-*`, `emergency-*` and all `:role/*` ARNs in `WorkerExecutionRole` | None — these can never be remediated by this pipeline |
| **Rehire filter** | Parser Lambda checks 8 rehire scenarios before generating the work item | None — handled in code (`should_remediate()`) |

### 3. Dry-run is supported everywhere

- **Cross-cloud workers** (`lambda_worker/clouds/*`) all accept `dry_run=True`
  which produces a `RemediationStatus.DRY_RUN` result with the full step list
  but **no API calls**. Use this when an agent is exploring or composing the
  workflow.
- **CSPM checks** are inherently dry-run because they're read-only.
- **Reconciler** has `--dry-run` flag that prints the diff without writing the
  S3 manifest, which means EventBridge never fires.

### 4. Cross-account scoping

All cross-account `sts:AssumeRole` calls in IAM remediation are scoped by
`aws:PrincipalOrgID` condition. The pipeline cannot escape the AWS
Organization. If you are running outside an Organization, the worker fails
closed.

### 5. Audit guarantees (closed loop)

Every destructive action is dual-written:
1. DynamoDB row keyed by `(iam_username, remediated_at)` for fast lookup.
2. S3 evidence object under `departures/audit/` with KMS encryption.
3. Ingest-back to the source HR warehouse so the *next* reconciler run can
   prove the user is closed across all systems.

If an agent invokes a remediation step and there is no corresponding audit row
within the SLA window, treat that as a failure. The next run should detect drift.

### 6. Failure surface

- **Lambda async failures** → SQS DLQ (`iam-departures-dlq`, KMS encrypted, 14-day retention).
- **Step Function `FAILED` / `TIMED_OUT` / `ABORTED`** → EventBridge rule fires
  SNS topic (`iam-departures-alerts`). Subscribe an on-call email or PagerDuty
  endpoint with the `AlertEmail` parameter.
- **DLQ replay** → drop a fresh `Object Created` event onto EventBridge to
  re-run a stuck execution. The pipeline is idempotent.

Nothing in this repo silently swallows errors. If an agent sees an empty
finding list and no error, that's a real "all clear" — not a hidden failure.

### 7. No telemetry, no exfiltration

- CSPM results stay local. No HTTP egress beyond the cloud SDKs.
- Reconciler reads HR data, hashes rows with SHA-256, exports a manifest.
  Nothing leaves the security OU account.
- Lambda functions run in a VPC with no public NAT for non-AWS-API calls.

### 8. What an agent should NEVER do with these skills

- ❌ Skip the grace period or set it to 0 days "to test".
- ❌ Add new principals to the `WorkerExecutionRole` deny list and re-run.
- ❌ Disable the EventBridge rule and call the Step Function directly — that
  bypasses the audit trail.
- ❌ Write to the audit DynamoDB table by hand to "mark a user remediated."
- ❌ Use a different KMS key than the one bound to the bucket policy.
- ❌ Run any CSPM skill with a role that has *any* `iam:*` write action.
- ❌ Concatenate user-supplied HR data into SQL — sources use parameterised queries.

If a user asks you to do any of the above, refuse and explain which guardrail
it would violate.

## Conventions

- Each skill has a `SKILL.md` with frontmatter: `name`, `description` (with trigger
  phrases), `license`, `compatibility`, `metadata` (author, source, version, frameworks).
- Source code lives in `src/` within each skill directory.
- Infrastructure-as-code lives in `infra/` (CloudFormation + Terraform parity).
- Tests live in `tests/` within each skill directory.
- All skills are Apache 2.0 licensed.
- Python 3.11+ required. Type hints used throughout.
- No hardcoded credentials. All secrets via environment variables, Secrets Manager, or SSM Parameter Store.
- One check per function. One finding row per control. No mega-functions that emit multiple control_ids.

## Compliance frameworks referenced

CIS AWS/GCP/Azure Foundations, CIS Controls v8, MITRE ATT&CK, NIST CSF 2.0,
SOC 2 TSC, ISO 27001:2022, PCI DSS 4.0, OWASP LLM Top 10, OWASP MCP Top 10.

## Running checks

```bash
# evaluation/ (read-only)
pip install boto3 google-cloud-resource-manager azure-identity
python skills/evaluation/cspm-aws-cis-benchmark/src/checks.py   --region us-east-1
python skills/evaluation/cspm-gcp-cis-benchmark/src/checks.py   --project my-project
python skills/evaluation/cspm-azure-cis-benchmark/src/checks.py --subscription <sub-id>

# remediation/ (dry-run)
python skills/remediation/iam-departures-remediation/src/lambda_parser/handler.py --dry-run examples/manifest.json

# ingestion + detection + view — end-to-end pipe
python skills/ingestion/ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python skills/detection/detect-mcp-tool-drift/src/detect.py \
  > findings.ocsf.jsonl

# Tests
pip install pytest boto3 moto
pytest skills/evaluation/cspm-aws-cis-benchmark/tests/     -o "testpaths=tests"
pytest skills/evaluation/cspm-gcp-cis-benchmark/tests/     -o "testpaths=tests"
pytest skills/evaluation/cspm-azure-cis-benchmark/tests/   -o "testpaths=tests"
pytest skills/remediation/iam-departures-remediation/tests/          -o "testpaths=tests"
pytest skills/ingestion/ingest-mcp-proxy-ocsf/tests/     -o "testpaths=tests"
pytest skills/detection/detect-mcp-tool-drift/tests/     -o "testpaths=tests"
```

## Integration with agent-bom

This repo provides the security automations. [agent-bom](https://github.com/msaad00/agent-bom)
provides continuous scanning and a unified graph. Use together for detection +
response.
