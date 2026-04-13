# Changelog

All notable changes to `cloud-security` should be recorded here.

This changelog is intentionally **repo-level**, not per-skill semver. The repo
is released as one trust boundary: one CI bar, one MCP wrapper, one validation
model, one security posture. Individual skills track maturity and contract
metadata inside their own docs.

The format is loosely based on Keep a Changelog.

## Unreleased

### Added
- Repo-wide `CHANGELOG.md` to make material architecture, security, and skill changes discoverable without reading every PR.
- [`docs/FRAMEWORK_MAPPINGS.md`](docs/FRAMEWORK_MAPPINGS.md) to consolidate ATT&CK, ATLAS, CIS, NIST, OWASP, SOC 2, ISO, and PCI coverage across the repo.

### Changed
- Removed the redirect-only `skills/ai-infra-security/` and `skills/compliance-cis-mitre/` stubs after the layered skill reshape settled.
- Reframed `skills/detection-engineering/` as a shared OCSF contract and golden-fixture namespace rather than a temporary transition root.

### Documentation
- Clarified the repo-level release model: one repo version, lightweight per-skill contract metadata, no full per-skill semver yet.

## 0.3.0

### Added
- Thin local MCP wrapper under `mcp-server/` for project-scoped skill discovery and execution.
- Safe-skill CI bar and repo-level skill contract enforcement.
- Architecture visuals and refreshed public positioning docs.
- GCP parity skills:
  - `ingest-vpc-flow-logs-gcp-ocsf`
  - `ingest-gcp-scc-ocsf`
- Azure parity skills:
  - `ingest-nsg-flow-logs-azure-ocsf`
  - `ingest-azure-defender-for-cloud-ocsf`

### Changed
- Reorganized the repo into layered skill categories:
  - `ingestion/`
  - `detection/`
  - `evaluation/`
  - `view/`
  - `remediation/`
- Renamed and generalized `detect-lateral-movement-aws` to `detect-lateral-movement`.
- Expanded docs around execution modes, approval boundaries, Claude/agent usage, and the repo safety model.

### Security
- Fixed prior SQL-injection and unsafe identifier-handling issues in Snowflake and reconciler flows.
- Tightened event validation and dry-run enforcement for write-capable skills.
- Added centralized validator coverage for skill contract and safety checks.

### Testing
- Grew test coverage and parity validation substantially across skills, integration flows, and MCP discovery.

## 0.2.0

### Added
- Layered skill catalog with stronger CI, dependency hygiene, and repo baseline hardening.
- New ingestion, detection, evaluation, and AI-infra skills beyond the original CSPM/remediation set.

### Changed
- README, AGENTS, and architecture docs shifted from narrow CSPM wording to broader cloud + AI security skills framing.

## 0.1.0

### Added
- Initial cloud-security skills collection:
  - cloud posture / CIS evaluation
  - IAM departures remediation
  - OCSF-based ingestion and conversion foundations
