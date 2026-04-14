# Changelog

All notable changes to `cloud-ai-security-skills` should be recorded here.

This changelog is intentionally **repo-level**, not per-skill semver. The repo
is released as one trust boundary: one CI bar, one MCP wrapper, one validation
model, one security posture. Individual skills track maturity and contract
metadata inside their own docs.

The format is loosely based on Keep a Changelog.

## Unreleased

### Added

- [`docs/NATIVE_VS_OCSF.md`](docs/NATIVE_VS_OCSF.md) and [`docs/STATE_AND_TIMELINE_MODEL.md`](docs/STATE_AND_TIMELINE_MODEL.md) to make `native`, `canonical`, `ocsf`, and `bridge` modes explicit and to pin historical-state, tombstone, and timeline expectations across just-in-time and persistent runs.
- [`docs/DEBUGGING.md`](docs/DEBUGGING.md) and [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) for operator-facing format, CI, and runtime troubleshooting.
- `ingest-okta-system-log-ocsf` as the first external identity-vendor ingestion skill, mapping verified Okta System Log session, user lifecycle, and membership events into OCSF Authentication (3002), Account Change (3001), and User Access Management (3005).
- `detect-okta-mfa-fatigue` as the first Okta-native detection skill, emitting OCSF Detection Finding (2004) for repeated Okta Verify push challenge and denial bursts aligned to MITRE ATT&CK T1621.
- `ingest-entra-directory-audit-ocsf` as the Microsoft Entra / Graph identity-audit ingestion skill, mapping verified `directoryAudit` application, service-principal, app-role-assignment, and federated-credential events into OCSF API Activity (6003).
- `ingest-google-workspace-login-ocsf` as the Google Workspace identity-audit ingestion skill, mapping verified Admin SDK Reports login audit events into OCSF Authentication (3002) and Account Change (3001) while preserving Workspace natural IDs and event parameters.
- `detect-google-workspace-suspicious-login` as the first Google Workspace-native detection skill, emitting OCSF Detection Finding (2004) for provider-marked suspicious logins and repeated Workspace login failures followed by success, aligned to MITRE ATT&CK T1110 and T1078.
- `detect-entra-role-grant-escalation` as the narrow Entra follow-up detector for successful app-role assignments to service principals, aligned to MITRE ATT&CK `T1098.003` Additional Cloud Roles.
- a phased native/OCSF pilot for `ingest-cloudtrail-ocsf` and `detect-lateral-movement`, including explicit `--output-format {ocsf,native}` support, native/canonical-friendly test coverage, and MCP output-format selection for supported skills.
- repo-wide skill frontmatter for `approval_model`, `execution_modes`, and `side_effects`, plus CI enforcement and MCP tool-surface hints so human-in-the-loop expectations are explicit instead of inferred.
- optional `caller_roles`, `approver_roles`, and `min_approvers` contract metadata plus MCP caller-context propagation into write-capable skills, so remediation audit trails can record who invoked, who approved, and which request or session triggered the action.
- stderr-based MCP invocation audit events covering tool name, caller-context presence, approval-context presence, hashed arguments, duration, and exit status without logging raw stdin payloads.
- a shared opt-in `stderr` telemetry helper plus pilot JSON telemetry in `ingest-cloudtrail-ocsf` and `detect-lateral-movement`, enabled by `SKILL_LOG_FORMAT=json` or `AGENT_TELEMETRY=1` while preserving existing plain-text warnings by default.
- extended the structured `stderr` telemetry pilot to `ingest-k8s-audit-ocsf` and `detect-privilege-escalation-k8s`, so the Kubernetes ingest/detect path now has the same opt-in machine-readable runtime hints as the CloudTrail/lateral-movement path.
- extended the same opt-in structured `stderr` telemetry pilot to `ingest-okta-system-log-ocsf` and `detect-okta-mfa-fatigue`, covering the Okta identity ingest/detect path without changing stdout data contracts.
- extended the same opt-in structured `stderr` telemetry pilot to `ingest-google-workspace-login-ocsf` and `detect-google-workspace-suspicious-login`, covering the Google Workspace identity ingest/detect path without changing stdout data contracts.
- tightened the README and skill catalog entry path around use cases, skill selection, plug-in surfaces, and clearer layer guidance, plus added `docs/USE_CASES.md` as the practical crosswalk for sources, assets, frameworks, and starting skills.
- clarified in the README and use-case guide that repo-owned remediation audit lands in DynamoDB + S3 today, while customer-controlled sinks such as Snowflake / Snowpipe belong to the planned sink / runner layer rather than the currently shipped generic path.
- a new start-here visual and updated IAM departures data-flow visual so operators can see sources, layer choice, outputs, runtime surfaces, and the shipped-vs-optional sink boundary without reading the full architecture docs first.
- a runtime-surfaces visual showing that CLI, CI, MCP, and persistent wrappers all call the same `SKILL.md + src/ + tests/` contract instead of creating parallel implementations.
- `docs/CANONICAL_SCHEMA.md` and `docs/DATA_FLOW.md` to pin the repo-owned canonical model and the raw → canonical → native / ocsf / bridge flow.

### Changed

- trimmed the handful of overlong `SKILL.md` frontmatter descriptions so tool-selection metadata stays concise for Claude, Codex, Cursor, Windsurf, Cortex, and MCP clients.
- added optional `network_egress` skill metadata, exposed it through the MCP tool registry, and documented it in the skill/runtime contracts for sandbox-aware wrappers.
- added an explicit `## Do NOT do` anti-pattern section to `iam-departures-remediation` and surfaced network egress allowlist hints for the write-capable workflow.
- Expanded the coverage registry and framework mapping docs to track Okta, Entra / Graph, and Google Workspace as first-class OCSF identity-ingestion sources and detections.
- Expanded `ingest-okta-system-log-ocsf` to cover the verified Okta Verify push and denial event families needed for narrow MFA fatigue detection.
- Reframed the repo contract so OCSF remains a first-class interoperability option, but not a mandatory storage or execution model; the stable internal contract is now explicitly source truth -> canonical model -> `native` / `ocsf` / `bridge` output.
- Made the OCSF metadata validator format-aware so native-mode support does not weaken the OCSF path contract.
- Extended the native/OCSF pilot to `ingest-vpc-flow-logs-ocsf`, so AWS flow logs can now emit either OCSF Network Activity or the repo's canonical native network-flow shape while preserving a compatible end-to-end lateral-movement path.
- Extended the native/OCSF pilot to `ingest-k8s-audit-ocsf` and `detect-sensitive-secret-read-k8s`, so Kubernetes audit ingestion and one Kubernetes detector now support the same dual-mode rollout pattern as the earlier CloudTrail / VPC / lateral-movement pilots.
- Extended the native/OCSF pilot to `detect-privilege-escalation-k8s`, so the main windowed Kubernetes privilege-escalation detector now accepts native or OCSF input and can emit native or OCSF findings.
- Extended the native/OCSF pilot to `ingest-mcp-proxy-ocsf` and `detect-mcp-tool-drift`, so the MCP application-activity ingestion and tool-drift detection path now supports native or OCSF input/output without changing the core drift logic.
- Extended the native/OCSF pilot to `ingest-google-workspace-login-ocsf` and `detect-google-workspace-suspicious-login`, so the Workspace login ingestion and suspicious-login detection path now supports native or OCSF input/output without changing the underlying detection semantics.
- Extended the native/OCSF pilot to `ingest-entra-directory-audit-ocsf` and `detect-entra-credential-addition`, so Entra directory-audit ingestion and credential-addition detection now support native or OCSF input/output without changing the underlying detection semantics.
- Extended the native/OCSF pilot to `ingest-okta-system-log-ocsf` and `detect-okta-mfa-fatigue`, so the Okta System Log ingestion and MFA-fatigue detection path now supports native or OCSF input/output without changing the underlying detection semantics.
- Made the README honest about current schema-mode rollout, required `input_formats` / `output_formats` for every shipped skill, and documented the native output fields on the currently dual-mode skills.
- Added a runnable README hello-world path, clarified that the `DATA_FLOW.md` rollout list is now driven by README + `SKILL.md` frontmatter, and documented bounded-batch guidance for `detect-lateral-movement`.

- `docs/COVERAGE_MODEL.md`, `docs/framework-coverage.json`, and `docs/ROADMAP.md` to make framework, provider, asset, and execution coverage measurable and auditable.
- `scripts/validate_framework_coverage.py` so CI can reject undocumented or drifting coverage claims.
- explicit cross-cloud ATT&CK identity coverage metadata for `detect-lateral-movement`, covering AWS role pivots, GCP service-account pivots, and Azure role / managed-identity pivot anchors.
- explicit MITRE ATLAS and NIST AI RMF declarations for `gpu-cluster-security`, including machine-readable benchmark metadata for wrappers and coverage tests.
- `docs/RUNTIME_ISOLATION.md` to document sandboxing, credential scope, transport protections, integrity controls, and approval rules across CLI, CI, MCP, and persistent/serverless runs.
- Added deterministic `metadata.uid` to OCSF emitters and discovery bridge events for replay-safe SIEM dedupe.
- Added [`docs/SIEM_INDEX_GUIDE.md`](docs/SIEM_INDEX_GUIDE.md) covering index fields, timestamps, dedupe keys, and just-in-time vs persistent ingestion guidance.
- Added Azure Entra / Microsoft Graph credential-pivot coverage to `detect-lateral-movement`, including application and service-principal password-key changes, app-role grants, and federated identity credential creation.
- Added explicit NIST AI RMF traceability to `model-serving-security` and `discover-cloud-control-evidence`, including machine-readable benchmark metadata and an opt-in `ai-rmf` evidence mode.

### Changed
- Promoted the IAM departures cross-cloud workflow visual in `README.md` and made the CI badge explicitly track the `main` branch.
- Rebranded the public repo/docs surface to `cloud-ai-security-skills`, updated the MCP server name and project-scoped `.mcp.json`, and added a concise agent quick-start matrix for Claude Code, Codex, Cursor, Windsurf, and Cortex Code CLI.
- Normalized emitted OCSF and SARIF product/vendor identity to `cloud-ai-security-skills` while explicitly keeping older repo-local bridge/profile identifiers stable for compatibility.

## 0.4.0 - 2026-04-13

### Added
- Repo-wide `CHANGELOG.md` to make material architecture, security, and skill changes discoverable without reading every PR.
- [`docs/FRAMEWORK_MAPPINGS.md`](docs/FRAMEWORK_MAPPINGS.md) to consolidate ATT&CK, ATLAS, CIS, NIST, OWASP, SOC 2, ISO, and PCI coverage across the repo.
- First `discovery/` layer AI BOM skill, `discover-ai-bom`, which turns AI asset inventory snapshots into a deterministic CycloneDX-aligned BOM.
- First discovery-layer technical evidence skill, `discover-control-evidence`, which turns discovery artifacts into deterministic PCI / SOC 2 evidence JSON.
- `discover-cloud-control-evidence`, which turns AWS, GCP, and Azure inventory snapshots into deterministic PCI / SOC 2 technical evidence JSON.
- `discover-cloud-control-evidence --output-format ocsf-live-evidence`, which emits an OCSF Discovery / Live Evidence Info `[5040]` bridge event while preserving the native evidence document under `unmapped`.
- `discover-environment --output-format ocsf-cloud-resources-inventory`, which emits an OCSF Discovery / Cloud Resources Inventory Info `[5023]` bridge event while preserving the native environment graph under `unmapped`.
- deeper AI provider inventory and evidence coverage across AWS Bedrock / SageMaker, Google Vertex AI, Azure ML, and Azure AI Foundry in the discovery layer.
- deeper AI evaluation coverage in `model-serving-security`, including provider-shaped endpoint configs for SageMaker, Bedrock, Vertex AI, Azure ML, and Azure AI Foundry.

### Changed
- Removed the redirect-only `skills/ai-infra-security/` and `skills/compliance-cis-mitre/` stubs after the layered skill reshape settled.
- Reframed `skills/detection-engineering/` as a shared OCSF contract and golden-fixture namespace rather than a temporary transition root.
- Collapsed the largest CI matrices into grouped test lanes and added workflow concurrency so superseded PR runs cancel instead of flooding the queue.
- Added repo-level dependency/import consistency validation and aligned missing cloud SDK declarations in `pyproject.toml`.
- Moved `discover-environment` into the canonical `skills/discovery/` layer and wired discovery into the grouped `test-ai-infra` lane.

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
