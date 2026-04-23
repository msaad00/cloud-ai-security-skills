# References — remediate-mcp-tool-quarantine

## Model Context Protocol

- Spec — https://modelcontextprotocol.io/specification
- Tools concept — https://modelcontextprotocol.io/docs/concepts/tools
- The MCP spec defines tool discovery via `tools/list`; clients are free to filter that list before exposing tools to the agent. This skill produces the structured artifact (the JSONL quarantine file) that operators wire into their client's filter logic.

## MITRE ATT&CK + ATLAS

- T1195.001 — Compromise Software Supply Chain: https://attack.mitre.org/techniques/T1195/001/ (the rug-pull / tool-poisoning pattern caught by `detect-mcp-tool-drift`)
- TA0001 — Initial Access (parent tactic): https://attack.mitre.org/tactics/TA0001/
- MITRE ATLAS AML.T0051 — Prompt Injection: https://atlas.mitre.org/techniques/AML.T0051/ (the suspicious-description pattern caught by `detect-prompt-injection-mcp-proxy`)

## OWASP

- OWASP Top 10 for MCP (community draft) — referenced in [`docs/FRAMEWORK_MAPPINGS.md`](../../../docs/FRAMEWORK_MAPPINGS.md)
- OWASP LLM02 Insecure Output Handling and LLM05 Improper Output Handling are adjacent — quarantining a tool that emits manipulated output is a direct mitigation.

## OCSF 1.8

- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding
- The two source detectors (`detect-mcp-tool-drift`, `detect-prompt-injection-mcp-proxy`) emit class 2004 findings; this skill consumes the `observables[]` array and `metadata.product.feature.name` for source-skill provenance.

## AWS audit infrastructure (reused from sister remediation skills)

- DynamoDB `PutItem` — https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
- S3 server-side encryption with KMS (`aws:kms`) — https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
- Audit table partition key is `tool_name`, sort key `action_at` (ISO-8601 UTC). Compatible with the existing audit table schema used by `remediate-okta-session-kill` and `remediate-container-escape-k8s` — operators can reuse one table or split per-skill at deployment time.

## Repo-internal contracts this skill conforms to

- [`_shared/remediation_verifier.py`](../../_shared/remediation_verifier.py) — `build_verification_record()` + `build_drift_finding()` integration (per workflow convention, integrated from day one — see PR #305)
- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — 11-principle contract; this skill satisfies all destructive-write principles
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — `human_required` approval model with `min_approvers: 2`
- [`scripts/validate_safe_skill_bar.py`](../../../scripts/validate_safe_skill_bar.py) — enforces dry-run default, deny-list presence

## Compliance frameworks

- NIST CSF 2.0 — `RS.MI` (Mitigation): contain incidents to prevent expansion of compromise
- SOC 2 — CC7.4 (System operations: incident response)
- OWASP MCP Top 10 — supply-chain compromise + prompt-injection mitigation classes
