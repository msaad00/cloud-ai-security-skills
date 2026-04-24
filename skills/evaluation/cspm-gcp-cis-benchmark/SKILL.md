---
name: cspm-gcp-cis-benchmark
description: >-
  Assess GCP projects against a curated subset of CIS GCP Foundations Benchmark v3.0
  controls. Automates 10 high-impact read-only checks across IAM, Cloud Storage,
  logging, and VPC networking. Use when the user mentions GCP CIS benchmark, GCP
  security posture, service account key audit, audit logging coverage, or public
  bucket detection. Do NOT use for AWS or Azure;
  do NOT use to remediate findings (assessment-only, zero write permissions); do NOT
  claim full CIS GCP coverage — only 10 controls are implemented, see the Roadmap
  section in this file for the gap.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: operator_coordinated
compatibility: >-
  Requires Python 3.11+, google-cloud-iam, google-cloud-storage, google-cloud-compute.
  Service account needs roles/viewer + roles/iam.securityReviewer.
  No write permissions — assessment only.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/evaluation/cspm-gcp-cis-benchmark
  version: 0.1.0
  frameworks:
    - CIS GCP Foundations v3.0 (subset)
    - NIST CSF 2.0
    - ISO 27001:2022
  cloud: gcp
---

# CSPM — GCP CIS Foundations Benchmark v3.0 (subset)

Automated assessment of GCP projects against a curated subset of CIS GCP
Foundations Benchmark v3.0. The full benchmark has 80+ controls; this skill
implements **10 high-impact checks** that cover the most common findings on
real GCP projects. Each check is mapped to NIST CSF 2.0.

> **Honest scope:** the table below lists *only* what `src/checks.py` actually
> implements. See the **Roadmap** at the bottom for controls that are documented
> by CIS but not yet automated here. Contributions welcome — one check per function,
> one finding row per control.

## When to Use

- GCP project security posture assessment
- Pre-audit for SOC 2, ISO 27001, FedRAMP
- New project baseline validation
- Service account key hygiene audit
- Audit logging coverage review

## Architecture

Closed loop: scan → finding → fix (PR or console) → re-scan to verify the same `control_id` is now `pass`.

```mermaid
flowchart LR
    subgraph GCP["GCP Project — read-only"]
        IAM["IAM & Service Accounts<br/>3 checks"]
        GCS["Cloud Storage<br/>2 checks"]
        LOG["Audit Logging<br/>1 check"]
        NET["VPC / Firewall<br/>4 checks"]
    end

    CHK["checks.py<br/>10 CIS v3.0 controls<br/>roles/viewer + iam.securityReviewer"]
    OUT["Findings<br/>JSON · Console"]
    FIX["Remediation<br/>IaC PR · console fix<br/>or exception with TTL"]
    VERIFY["Re-scan<br/>control_id == pass"]

    IAM & GCS & LOG & NET --> CHK --> OUT --> FIX --> VERIFY
    VERIFY -. drift detected .-> CHK

    style GCP fill:#1e293b,stroke:#475569,color:#e2e8f0
    style CHK fill:#172554,stroke:#3b82f6,color:#e2e8f0
    style OUT fill:#1e3a5f,stroke:#60a5fa,color:#e2e8f0
    style FIX fill:#1a2e35,stroke:#2dd4bf,color:#e2e8f0
    style VERIFY fill:#164e63,stroke:#22d3ee,color:#e2e8f0
```

## Security Guardrails

- **Read-only**: Requires `roles/viewer` + `roles/iam.securityReviewer`. Zero write permissions.
- **No credentials stored**: GCP credentials from ADC (Application Default Credentials) only.
- **No data exfiltration**: Results stay local. No calls beyond GCP SDK.
- **Least privilege**: reads project IAM policy, bucket posture, VPC networks, and subnet attributes only.
- **Idempotent**: Run as often as needed with no side effects.

## Implemented Controls (10)

Each row maps to one function in `src/checks.py`. If it's not in this table, it's not implemented.

### Section 1 — IAM (3 checks)

| # | CIS Control | Function | Severity | NIST CSF 2.0 |
|---|------------|----------|----------|--------------|
| 1.1 | Corporate credentials only (no personal Gmail) | `check_1_1_no_gmail_accounts` | HIGH | PR.AC-1 |
| 1.3 | No user-managed service account keys | `check_1_3_no_sa_keys` | HIGH | PR.AC-1 |
| 1.4 | Service account key rotation (90 days) | `check_1_4_sa_key_rotation` | MEDIUM | PR.AC-1 |

### Section 2 — Cloud Storage (2 checks)

| # | CIS Control | Function | Severity | NIST CSF 2.0 |
|---|------------|----------|----------|--------------|
| 2.1 | Uniform bucket-level access (no legacy ACL) | `check_2_1_uniform_access` | HIGH | PR.AC-3 |
| 2.3 | No public buckets (allUsers/allAuthenticatedUsers) | `check_2_3_no_public_buckets` | CRITICAL | PR.AC-3 |

### Section 3 — Logging (1 check)

| # | CIS Control | Function | Severity | NIST CSF 2.0 |
|---|------------|----------|----------|--------------|
| 3.1 | Audit logging on `allServices` for Admin Read, Data Read, and Data Write with no exemptions | `check_3_1_audit_logging_all_services` | HIGH | DE.AE-3 |

### Section 4 — Networking (4 checks)

| # | CIS Control | Function | Severity | NIST CSF 2.0 |
|---|------------|----------|----------|--------------|
| 4.1 | Default VPC deleted | `check_4_1_default_network_deleted` | HIGH | PR.AC-5 |
| 4.2 | No unrestricted SSH/RDP (0.0.0.0/0 on 22/3389) | `check_4_2_no_unrestricted_ssh_rdp` | HIGH | PR.AC-5 |
| 4.3 | VPC flow logs on all subnets | `check_4_3_vpc_flow_logs` | MEDIUM | DE.CM-1 |
| 4.4 | Private Google Access on all subnets | `check_4_4_private_google_access` | MEDIUM | PR.AC-5 |

## Roadmap — Documented but Not Yet Automated

These controls are part of the CIS GCP Foundations v3.0 benchmark but are *not* implemented in `checks.py` yet. PRs welcome.

| # | CIS Control | Why it matters |
|---|------------|----------------|
| 1.2 | MFA enforced org-wide | Requires Workspace Admin SDK access, not in this skill's scope |
| 1.5 | No keys for default compute/App Engine SAs | Specialised filter on top of 1.3 |
| 1.6 | No project-wide SSH keys | Compute metadata read |
| 1.7 | SA impersonation scoped | IAM Recommender or policy walker |
| 2.2 | Bucket retention policy on compliance buckets | Requires labeling convention |
| 2.4 | CMEK encryption on sensitive data | KMS + Storage join |
| 3.2–3.4 | Logging metrics and alert policies | `google-cloud-logging` + `google-cloud-monitoring` |
| 4.5 | SSL policies enforce TLS 1.2+ | Compute API SSL policies |

## Usage

```bash
# Run all checks
python src/checks.py --project my-project-id

# Run specific section
python src/checks.py --project my-project-id --section iam
python src/checks.py --project my-project-id --section logging
python src/checks.py --project my-project-id --section networking

# Output JSON
python src/checks.py --project my-project-id --output json --output-format ocsf > cis-gcp-results.json
```

## Remediation — Critical Findings

```
  FINDING: Public Cloud Storage bucket (2.3)
  ───────────────────────────────────────────
  FIX:     gsutil iam ch -d allUsers gs://BUCKET
           gsutil iam ch -d allAuthenticatedUsers gs://BUCKET
  VERIFY:  gsutil iam get gs://BUCKET | grep -c "allUsers"  # should be 0
```

```
  FINDING: Audit logging coverage missing on allServices (3.1)
  ───────────────────────────────────────────────────────────
  FIX:     gcloud projects get-iam-policy PROJECT_ID --format=json > policy.json
           # add allServices auditConfigs for ADMIN_READ, DATA_READ, DATA_WRITE
           gcloud projects set-iam-policy PROJECT_ID policy.json
  VERIFY:  python src/checks.py --project PROJECT_ID --section logging
```

## Posture Metrics

| Metric | Target |
|--------|--------|
| CIS Pass Rate | > 90% |
| Service Accounts with User Keys | 0 |
| Public Buckets | 0 |
| Default VPC Present | 0 |
| Subnets without Flow Logs | 0 |
| Subnets without Private Google Access | 0 |
| Audit Logging Coverage | 100% of services |
