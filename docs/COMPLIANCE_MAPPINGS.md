# Compliance Mappings

This document maps the repo's shipped contracts and controls to the compliance
frameworks procurement reviewers most often ask about:

- SOC 2 Trust Services Criteria (common criteria)
- ISO/IEC 27001:2022 Annex A

This is a control-support mapping, not a certification claim.

It tells a reviewer:

- which repo controls materially support a control objective
- where the evidence lives in this repo
- which responsibilities remain with the operator or customer

Read next:

- [../SECURITY.md](../SECURITY.md)
- [../SECURITY_BAR.md](../SECURITY_BAR.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [DATA_HANDLING.md](DATA_HANDLING.md)
- [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)

## Scope And Interpretation

What this document does:

- maps shipped repo controls to compliance objectives
- points to code, docs, and contracts that substantiate those controls
- identifies the repo's side of shared-responsibility boundaries

What this document does not do:

- claim that the repo alone satisfies a full SOC 2 or ISO 27001 program
- replace operator IAM, key management, retention, HR, change-management, or
  incident-response processes
- assert third-party certifications for cloud vendors, SaaS providers, or
  customer environments

Short rule:

- repo controls support compliance
- operators still own deployment, identity, retention, and organizational policy

## Control Evidence In This Repo

Common evidence sources used below:

- [../SECURITY_BAR.md](../SECURITY_BAR.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md)
- [SCHEMA_VERSIONING.md](SCHEMA_VERSIONING.md)
- [ERROR_CODES.md](ERROR_CODES.md)
- [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)
- [CREDENTIAL_PROVENANCE.md](CREDENTIAL_PROVENANCE.md)
- `SKILL.md` frontmatter and `Do NOT use` sections
- CI and release workflows under `.github/workflows/`

## SOC 2 Trust Services Criteria

| SOC 2 criterion | Repo support today | Main evidence in repo | Notes / limits |
|---|---|---|---|
| `CC1.2` integrity and ethical values reflected in operations | real but indirect | `SECURITY_BAR.md`, `AGENTS.md`, skill contracts | supports secure engineering expectations, not corporate HR policy |
| `CC2.1` governance and oversight for security objectives | real but indirect | `SECURITY_BAR.md`, `DESIGN_DECISIONS.md`, PR-reviewed contracts | repo-level governance only; not a substitute for org governance |
| `CC3.2` risk identification and analysis | strong | `THREAT_MODEL.md`, `RUNTIME_ISOLATION.md`, `DATA_HANDLING.md` | documents assets, actors, scenarios, trust boundaries, and mitigations |
| `CC5.2` logical access and least privilege | strong | `SECURITY_BAR.md`, `CREDENTIAL_PROVENANCE.md`, per-skill `REFERENCES.md` | operator still owns actual IAM assignments in their environment |
| `CC6.1` logical access security software and infrastructure restrictions | strong | read-only-by-default contract, `SKILL.md` frontmatter, `RUNTIME_ISOLATION.md` | strongest on repo-owned skill behavior; customer infra remains customer-owned |
| `CC6.3` authorization before privileged or sensitive actions | strong | remediation and sink contracts, MCP approval gating, `THREAT_MODEL.md` | destructive actions require documented approval or dry-run gating |
| `CC6.6` transmission, processing, and storage protections | real | `RUNTIME_ISOLATION.md`, `DATA_HANDLING.md`, sink contracts | repo documents TLS, audit, and retention expectations; storage encryption is operator-owned |
| `CC6.7` restrict data transmission and prevent unauthorized disclosure | strong | no-telemetry posture, egress restrictions, secret-handling rules | strongest for repo behavior; customer sink and network policy still matter |
| `CC7.1` detect anomalies, threats, and failures | strong | ingest/detect/evaluate skills, golden fixtures, CI validation | this is one of the repo's strongest areas |
| `CC7.2` monitor system components and events | strong | detection-engineering surface, runners, sinks, evidence paths | monitoring output exists; central SOC workflow remains operator-owned |
| `CC7.3` evaluate security events and act | strong | `detect-*`, `view/*`, remediation workflow, audit trails | response orchestration beyond shipped workflows is still a customer choice |
| `CC7.4` incident response support | real | IAM departures remediation, sink audit paths, runner contracts | supports controlled response patterns, not a full org IR program |
| `CC8.1` change management and controlled deployment | strong | PR-reviewed docs/contracts, CI validation, signed SBOM, release checklist | repo change control is well covered; customer deployment change control is external |
| `CC9.2` mitigate vendor and supply-chain risk | strong | `SUPPLY_CHAIN.md`, signed SBOM, `pip-audit`, dependency policy | strong repo supply-chain story, but not a complete vendor-management program |

## ISO/IEC 27001:2022 Annex A

| Annex A control | Repo support today | Main evidence in repo | Notes / limits |
|---|---|---|---|
| `A.5.8` information security in project management | real | `DESIGN_DECISIONS.md`, `SECURITY_BAR.md`, CI policy | supports secure engineering discipline for this repo |
| `A.5.15` access control | strong | least-privilege skill design, credential hierarchy, frontmatter approval models | operator still owns enterprise IAM governance |
| `A.5.16` identity management | strong | `CREDENTIAL_PROVENANCE.md`, remediation identity flows, identity ingesters | strongest for repo-owned flows; not a directory-service policy replacement |
| `A.5.18` access rights | strong | `REFERENCES.md` required-permissions sections, read-only defaults | least-privilege design is explicit, but runtime assignments are customer-owned |
| `A.5.23` information security for use of cloud services | strong | cloud-specific skill contracts, runtime isolation, source/sink controls | repo gives patterns and constraints, not blanket cloud governance |
| `A.5.28` secure coding | strong | `SECURITY_BAR.md`, Bandit, validator scripts, error-path tests | one of the repo's strongest control areas |
| `A.5.30` ICT readiness for business continuity | partial | stateless skill model, runner templates, replay-safe patterns | continuity planning beyond repo patterns is operator-owned |
| `A.5.36` compliance with policies and standards | real | contract docs, framework mappings, CI validation | repo demonstrates enforcement of its own standards |
| `A.8.9` configuration management | strong | `SKILL.md`, versioned docs, fixed repo contracts, CI validation | supports repo configuration discipline |
| `A.8.12` data leakage prevention | strong | no-telemetry stance, secret handling, sink and runtime guardrails | strongest for repo behavior, not for customer exfiltration controls outside the repo |
| `A.8.15` logging | strong | stderr telemetry, MCP audit events, sink/remediation audit posture | schema docs for stderr and MCP audit are separate follow-up work |
| `A.8.16` monitoring activities | strong | detection, posture, evidence, and runner surfaces | central monitoring platform remains external |
| `A.8.20` network security | real | documented transport expectations, no generic network passthrough, sink/egress restrictions | operator still owns real network segmentation and firewalls |
| `A.8.24` use of cryptography | partial but real | TLS expectations, signed SBOM, documented encryption-at-rest expectations | customer key management remains external |
| `A.8.28` secure software development | strong | CI checks, threat model, signed release artifacts, supply-chain controls | another strong area for repo-owned controls |
| `A.8.30` outsourced development | partial | official-source-only references, dependency policy, release verification | supports supplier review but not a full outsourced development program |

## Strongest Compliance Themes

The repo is strongest where the control objective overlaps directly with how the
product is built:

- secure coding and defensive parsing
- least privilege and read-only defaults
- deterministic outputs and validation
- supply-chain transparency and signed artifacts
- monitoring, detection, and evidence generation
- human approval and audit on write-capable paths

## Shared Responsibility Boundaries

The following stay outside the repo's direct control and must be owned by the
operator, customer, or deploying organization:

- actual IAM role assignments and identity lifecycle
- network segmentation and firewall policy
- sink retention, legal hold, and residency settings
- incident response staffing and escalation policy
- enterprise change management and approval workflow
- customer key management, HSM, and encryption-at-rest enforcement
- vendor management and third-party due diligence beyond repo dependencies

## How To Use This In Review

For a procurement or security review:

1. start with the specific control row in this document
2. inspect the linked repo evidence
3. separate repo-owned controls from operator-owned controls
4. treat this mapping as technical evidence, not certification language

That keeps the claims accurate and reviewable.
