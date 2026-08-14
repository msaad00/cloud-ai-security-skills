# Documentation index

Every doc under `docs/`, grouped by what you're trying to do. Skill-level
behavior lives in each skill's `SKILL.md`; this index is the repo-wide map.

> Docs marked _(generated)_ are produced by a script under `scripts/` and
> checked in CI — edit the generator, not the file.

## Start here

| Doc | What it covers |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | Run a pipeline locally in a few commands |
| [AGENT_QUICKSTART.md](AGENT_QUICKSTART.md) | Wire the skills into an MCP agent |
| [INSTALL.md](INSTALL.md) | Install and dependency groups |
| [USE_CASES.md](USE_CASES.md) | Pick the right skill for a job |
| [WHY.md](WHY.md) | Why this repo exists vs. rolling your own |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common failures and fixes |

## Architecture & design

| Doc | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Full layered architecture (the load-bearing design contract) |
| [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) | Why the big calls were made |
| [DATA_FLOW.md](DATA_FLOW.md) | How data moves through the layers |
| [STATE_AND_TIMELINE_MODEL.md](STATE_AND_TIMELINE_MODEL.md) | State and timeline semantics |
| [SKILL_COMPOSITION.md](SKILL_COMPOSITION.md) | Composing skills into pipelines |
| [ROADMAP.md](ROADMAP.md) | What's planned |

## Contracts

| Doc | What it covers |
|---|---|
| [SKILL_CONTRACT.md](SKILL_CONTRACT.md) | The contract every skill honors |
| [RUNNER_CONTRACT.md](RUNNER_CONTRACT.md) | Runner execution contract |
| [SINK_CONTRACT.md](SINK_CONTRACT.md) | Append-only sink contract |
| [MCP_AUDIT_CONTRACT.md](MCP_AUDIT_CONTRACT.md) | MCP audit envelope |
| [MCP_TRANSPORT.md](MCP_TRANSPORT.md) | MCP transport and wiring |
| [REMEDIATION_VERIFICATION.md](REMEDIATION_VERIFICATION.md) | Post-action re-verification contract |
| [HITL_POLICY.md](HITL_POLICY.md) | Human-in-the-loop approval bar per skill |
| [STDERR_TELEMETRY_CONTRACT.md](STDERR_TELEMETRY_CONTRACT.md) | stderr telemetry shape |
| [ERROR_CODES.md](ERROR_CODES.md) | Exit codes and error taxonomy |

## Schema & normalization

| Doc | What it covers |
|---|---|
| [CANONICAL_SCHEMA.md](CANONICAL_SCHEMA.md) | The canonical internal schema |
| [NATIVE_VS_OCSF.md](NATIVE_VS_OCSF.md) | When output is native vs. OCSF 1.8 |
| [NORMALIZATION_REFERENCE.md](NORMALIZATION_REFERENCE.md) | Field-by-field normalization reference |
| [NORMALIZATION_EXAMPLES.md](NORMALIZATION_EXAMPLES.md) | Worked normalization examples |
| [SCHEMA_VERSIONING.md](SCHEMA_VERSIONING.md) | Schema version policy |
| [SCHEMA_COVERAGE.md](SCHEMA_COVERAGE.md) | Which OCSF classes are covered |
| [MAPPING_COVERAGE.md](MAPPING_COVERAGE.md) | Field-mapping coverage audit |

## Coverage & frameworks

| Doc | What it covers |
|---|---|
| [SKILL_INDEX.md](SKILL_INDEX.md) | Find a skill fast |
| [COVERAGE_SNAPSHOT.md](COVERAGE_SNAPSHOT.md) | Live skill totals _(generated)_ |
| [FRAMEWORK_COVERAGE.md](FRAMEWORK_COVERAGE.md) | Per-framework control coverage _(generated)_ |
| [COVERAGE_MODEL.md](COVERAGE_MODEL.md) | How coverage is measured |
| [FRAMEWORK_MAPPINGS.md](FRAMEWORK_MAPPINGS.md) | Framework narrative + gaps |
| [COMPLIANCE_MAPPINGS.md](COMPLIANCE_MAPPINGS.md) | Procurement-reviewer control view |
| [INGEST_COVERAGE.md](INGEST_COVERAGE.md) | Vendor signals → OCSF classes |
| [SECURITY_GRADES.md](SECURITY_GRADES.md) | Per-skill security grades _(generated)_ |

## Security posture

| Doc | What it covers |
|---|---|
| [THREAT_MODEL.md](THREAT_MODEL.md) | Scenario-oriented threat model + coverage map |
| [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md) | Process/runtime isolation |
| [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) | Supply-chain and dependency trust |
| [CREDENTIAL_PROVENANCE.md](CREDENTIAL_PROVENANCE.md) | How credentials are sourced and scoped |
| [DATA_HANDLING.md](DATA_HANDLING.md) | Data handling and retention posture |
| [COMPLIANCE_EVIDENCE_CAPTURE.md](COMPLIANCE_EVIDENCE_CAPTURE.md) | UI evidence capture — when and how |

## Agents, harness & data lakes

| Doc | What it covers |
|---|---|
| [HARNESS.md](HARNESS.md) | Surfaces, knobs, and scope boundary |
| [AGENT_DATA_LAKE_FLOW.md](AGENT_DATA_LAKE_FLOW.md) | Agent → data-lake flow |
| [CLICKHOUSE_DATA_LAKE.md](CLICKHOUSE_DATA_LAKE.md) | ClickHouse security data lake |
| [SNOWFLAKE_DATA_LAKE.md](SNOWFLAKE_DATA_LAKE.md) | Snowflake security data lake |
| [SIEM_INDEX_GUIDE.md](SIEM_INDEX_GUIDE.md) | SIEM indexing guidance |
| [integrations/](integrations/) | Per-IDE / per-client MCP wiring |

## Runtime & operations

| Doc | What it covers |
|---|---|
| [RUNTIME_PROFILES.md](RUNTIME_PROFILES.md) | Runner-template runtime profiles _(generated)_ |
| [RUNTIME_PROFILES_SKILLS.md](RUNTIME_PROFILES_SKILLS.md) | Per-skill runtime guidance |
| [PERFORMANCE.md](PERFORMANCE.md) | Cold-start vs. warm-pool performance |
| [TESTING.md](TESTING.md) | Test surface and edge-case axes |
| [CI_WORKFLOW.md](CI_WORKFLOW.md) | What CI runs |
| [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) | Cutting a release |

## Source integrations & proposals

| Doc | What it covers |
|---|---|
| [WORKDAY_OCSF_DEPARTURES.md](WORKDAY_OCSF_DEPARTURES.md) | Workday departures → OCSF |
| [DEPENDENCY_HYGIENE_SKILL.md](DEPENDENCY_HYGIENE_SKILL.md) | Proposed skill spec (not yet shipped) |
