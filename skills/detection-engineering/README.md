# detection-engineering/

Detection rules, threat hunts, and runtime monitors for AI infrastructure and traditional cloud surfaces. This category answers the question:

> *What does an attack look like on this surface, and how do I see it the next time it happens?*

## Design principles

### 1. OCSF is the wire format between skills

Every skill in this category reads and writes **OCSF 1.8 JSONL** ([Open Cybersecurity Schema Framework](https://schema.ocsf.io/)). Skills do **not** import from each other — they compose via stdin/stdout pipes like Unix tools:

```bash
cat cloudtrail.json                                              \
  | python -m ingest_cloudtrail_ocsf                             \
  | python -m detect_credential_access_ocsf                      \
  | python -m ocsf_to_sarif > findings.sarif
```

This keeps every skill self-contained (per the Anthropic skills spec, which requires each skill to be a standalone bundle), and the OCSF contract is the only cross-skill dependency.

### 2. Three skill shapes

| Shape | Prefix | Input | Output | Example |
|---|---|---|---|---|
| **ingest** | `ingest-` | raw log (JSONL / JSON / NDJSON) from one source | OCSF event of the right class | `ingest-mcp-proxy-ocsf` |
| **detect** | `detect-` | OCSF events (any class) | **OCSF Detection Finding** (class 2004) | `detect-mcp-tool-drift` |
| **convert** | under `convert/` | OCSF Detection Finding | format for downstream tool | `convert/ocsf-to-sarif` |

A new log source = a new `ingest-*` skill. A new attack pattern = a new `detect-*` skill. A new downstream tool = a new `convert/*` skill. None of them need to know about the others beyond the OCSF contract.

### 3. MITRE ATT&CK lives inside OCSF, not alongside it

OCSF 1.8 Detection Finding has a first-class `attacks[]` field **inside `finding_info`** (the deprecated Security Finding layout put it at the event root — don't do that). Every detection must populate it with the appropriate tactic / technique / sub-technique. That's the pivot point for analytics later — you don't need a parallel MITRE mapping table because the mapping *is* the finding.

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "finding_info": {
    "uid": "det-mcp-drift-...",
    "attacks": [{
      "version": "v14",
      "tactic": {"name": "Initial Access", "uid": "TA0001"},
      "technique": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "uid": "T1195.001"}
    }]
  }
}
```

### 4. Golden fixtures, not mocks

Every detection skill tests against a **frozen OCSF fixture** in [`golden/`](golden/). When you add a new detection, the first thing you add is the input fixture (what the attack looks like on the wire) and the expected OCSF Detection Finding output. The test becomes a contract: *"given these events, this rule MUST produce this finding."* That's what makes detections refactorable without silent regressions.

### 5. Closed loop, same as every other category

Detection engineering closes the loop by being *checkable*: a finding is either present on the next run over the same fixture, or it isn't. If a refactor loses coverage, the golden test fails. If an attacker tweaks their technique, you add a new fixture and a new test; the old one stays green so you know you didn't lose old coverage.

## Current skills

| Skill | Shape | Surface | MITRE | Tests |
|---|---|---|---|---:|
| [`ingest-cloudtrail-ocsf`](ingest-cloudtrail-ocsf/) | ingest | AWS CloudTrail | n/a | 31 |
| [`ingest-gcp-audit-ocsf`](ingest-gcp-audit-ocsf/) | ingest | GCP Cloud Audit Logs | n/a | 31 |
| [`ingest-azure-activity-ocsf`](ingest-azure-activity-ocsf/) | ingest | Azure Activity Logs | n/a | 34 |
| [`ingest-k8s-audit-ocsf`](ingest-k8s-audit-ocsf/) | ingest | Kubernetes audit logs | n/a | 36 |
| [`ingest-mcp-proxy-ocsf`](ingest-mcp-proxy-ocsf/) | ingest | agent-bom MCP proxy | n/a | 20 |
| [`detect-mcp-tool-drift`](detect-mcp-tool-drift/) | detect | MCP tool schemas | T1195.001 | 22 |
| [`detect-privilege-escalation-k8s`](detect-privilege-escalation-k8s/) | detect | K8s OCSF API Activity | T1552.007, T1611, T1098, T1550.001 | 32 |

**206 tests total.** Every skill reads and writes OCSF 1.8 JSONL.

## Roadmap

The category is intentionally opinionated about what comes next. Every row below is a single skill with a single OCSF class as input and OCSF Detection Finding as output.

### Ingestion (`ingest-*`)

| Skill | Source | OCSF class produced | Status |
|---|---|---|---|
| `ingest-cloudtrail-ocsf` | AWS CloudTrail | API Activity (6003) | ✅ shipped |
| `ingest-gcp-audit-ocsf` | GCP Audit Logs | API Activity (6003) | ✅ shipped |
| `ingest-azure-activity-ocsf` | Azure Activity Logs | API Activity (6003) | ✅ shipped |
| `ingest-k8s-audit-ocsf` | Kubernetes audit logs | API Activity (6003) | ✅ shipped |
| `ingest-mcp-proxy-ocsf` | agent-bom MCP proxy | Application Activity (6002) | ✅ shipped |
| `ingest-model-serving-ocsf` | Model serving access logs | HTTP Activity (4002) | roadmap |
| `ingest-vector-store-ocsf` | Vector DB query logs | Application Activity (6002) | roadmap |
| `ingest-vm-audit-ocsf` | SSM / OS Login / VM activity | API Activity (6003) | roadmap |

### Detection (`detect-*`)

| Skill | Data source | MITRE | Status |
|---|---|---|---|
| `detect-mcp-tool-drift` | OCSF Application Activity (MCP) | T1195.001 | ✅ shipped |
| `detect-privilege-escalation-k8s` | OCSF API Activity (K8s) | T1552.007, T1611, T1098, T1550.001 | ✅ shipped |
| `detect-mcp-prompt-injection` | OCSF Application Activity (MCP) | T1565 Data Manipulation | roadmap |
| `detect-credential-access-aws` | OCSF API Activity (CloudTrail) | T1528, T1552 | roadmap |
| `detect-credential-access-gcp` | OCSF API Activity (GCP) | T1528, T1552 | roadmap |
| `detect-credential-access-azure` | OCSF API Activity (Azure) | T1528, T1552 | roadmap |
| `detect-unusual-assume-role` | OCSF API Activity (AWS) | T1548.005 | roadmap |
| `detect-gcp-iam-impersonation` | OCSF API Activity (GCP) | T1078.004 | roadmap |
| `detect-model-weight-tampering` | OCSF File System Activity + Application | T1565.001 | roadmap |
| `detect-vector-store-poisoning` | OCSF Application Activity (vector DB) | T1566.002 | roadmap |
| `detect-agent-to-agent-collusion` | OCSF Application Activity (multi-agent topology) | AI-specific, no T-code yet | roadmap |
| `detect-prompt-cache-poisoning` | OCSF Application Activity (inference) | AI-specific, no T-code yet | roadmap |

### Conversion (`convert/*`)

| Skill | From | To |
|---|---|---|
| `convert/ocsf-to-sarif` | OCSF Detection Finding | SARIF 2.1.0 (GitHub code scanning) |
| `convert/ocsf-to-sigma` | OCSF Detection Finding | Sigma rule (Splunk, Elastic, Sentinel) |
| `convert/ocsf-to-mermaid` | OCSF Detection Finding | Mermaid attack-flow diagram for PR comments |

## Analytics and visualization

Detections produce OCSF. Everything downstream consumes OCSF. See [`analytics/README.md`](analytics/README.md) for the target stack (ClickHouse + Grafana) and the OCSF-to-ClickHouse schema mapping.
