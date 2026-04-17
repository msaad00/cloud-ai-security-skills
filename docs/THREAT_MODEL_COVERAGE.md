# Threat Model Coverage

This document maps the high-signal scenarios in [THREAT_MODEL.md](THREAT_MODEL.md)
to concrete automated tests or an explicit documented exception.

It is intentionally short. The goal is to make coverage visible, not to
duplicate the threat model itself.

## Coverage Map

| Threat scenario | Coverage status | Evidence |
|---|---|---|
| Untrusted logs or findings attempt prompt injection or instruction smuggling into an agent flow | covered | `mcp-server/tests/test_server.py`, `mcp-server/tests/test_server_unit.py`, fixed-tool MCP wrapper, no arbitrary shell execution |
| A read-only skill performs hidden writes or undeclared side effects | covered | `tests/integration/test_skill_validation_scripts.py`, `scripts/validate_safe_skill_bar.py`, `scripts/validate_skill_contract.py` |
| SQL or shell injection through source adapters, sinks, or runners | covered | `skills/ingestion/source-snowflake-query/tests/test_ingest.py`, `skills/ingestion/source-databricks-query/tests/test_ingest.py`, `mcp-server/tests/test_server_unit.py` |
| Secrets, tokens, or connection strings leak into stdout, stderr, findings, or audit rows | partial, documented exception | CI secret scanning and reference policy are automated; repo-local automation cannot prove operators never pass secrets in live input. See `tests/integration/test_skill_validation_scripts.py`, [SECURITY.md](../SECURITY.md), and [CREDENTIAL_PROVENANCE.md](CREDENTIAL_PROVENANCE.md). |
| A remediation or sink path executes without real human approval | covered | `mcp-server/tests/test_server_unit.py`, `tests/integration/test_skill_validation_scripts.py`, `tests/integration/test_iam_departures_guardrails.py` |
| Replay or duplicate delivery causes duplicate findings or repeated writes | covered | `skills/detection/detect-lateral-movement/tests/test_detect.py`, `skills/remediation/iam-departures-remediation/tests/test_worker_lambda.py`, runner dedupe integration tests |
| Schema drift or deprecated vendor APIs silently corrupt outputs | covered | golden fixtures, `tests/integration/test_skill_validation_scripts.py`, `scripts/validate_ocsf_metadata.py`, `scripts/validate_framework_coverage.py` |
| Dependency or release tampering causes consumers to run untrusted code | partial, documented exception | SBOM generation, lockfile, dependency, and release workflow checks are automated. Tag/release consumption trust still depends on operator verification of published artifacts. See CI workflows, `tests/integration/test_skill_validation_scripts.py`, and [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md). |

## Notes

- `covered` means there is at least one automated test or validator that directly
  exercises the control.
- `partial, documented exception` means the repo can verify some of the contract
  locally, but full assurance depends on runtime/operator behavior outside the
  repo boundary.
