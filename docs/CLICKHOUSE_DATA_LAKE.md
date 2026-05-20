# ClickHouse security data lake — hero use case

This is the canonical end-to-end story for running cloud-ai-security-skills on
top of a ClickHouse-backed security data lake. It is one of three lake
patterns the repo supports (see [`AGENT_DATA_LAKE_FLOW.md`](AGENT_DATA_LAKE_FLOW.md)),
and the most fully wired one: write-side, read-side, and replay all live in
this repo.

The pattern is **agentless, append-only, and idempotent**. The skills mutate
no schema. The lake owns retention. Replays converge because every uid is
content-addressable.

> Want the schema instead? Jump to
> [`packs/clickhouse`](../packs/clickhouse/README.md). Want the wire
> contract? See [`SINK_CONTRACT.md`](SINK_CONTRACT.md).

## TL;DR

```
   any cloud / SaaS / IdP / K8s / MCP signal
                         │
                         ▼
                ingest-*  (15 skills)        ──── L1 normalize to OCSF 1.8
                         │
                         ▼
                sink-clickhouse-jsonl --apply ──── L7 append-only insert
                         │
                         ▼
   ┌──────────────────── ClickHouse ─────────────────────────┐
   │  security.events_sink     (90 d  — hot)                 │
   │  security.findings_sink   (365 d — warm)                │
   │  security.evidence_sink   (7 yr  — compliance hold)     │
   │  security.audit_sink      (legal-hold retention)        │
   │  security.findings_by_rule_hourly  (rollup MV)          │
   │  security.events_by_class_daily    (rollup MV)          │
   │  security.remediations_by_outcome_daily (rollup MV)     │
   └─────────────────────────────────────────────────────────┘
                         │
                         ▼
                source-clickhouse-query        ──── read-only SQL gate
                         │
                         ▼
                detect-*  (14 skills)          ──── L3 deterministic rules
                view-*    (2 skills)           ──── L6 SARIF / Mermaid
                discover-control-evidence      ──── L2 posture / compliance
                         │
                         ▼
                sink-clickhouse-jsonl --apply  ──── close the loop
```

Every box on that diagram is shipped today. No new code is needed to stand
the lake up — only the pack DDL and credentials.

## Why ClickHouse and not Snowflake / Security Lake / BigQuery

The repo's L7 ships three sinks because no single warehouse wins on every
axis. ClickHouse is the one we tell teams to run when **all five** of these
are true:

| Trait | ClickHouse position |
|---|---|
| Self-host **or** managed | First-class for both. ClickHouse Cloud + Helm chart. |
| Hot read latency | Sub-second scans of hundreds of millions of OCSF rows. |
| Cost per ingested row | The lowest of the three managed offerings at lake-scale. |
| Sovereign deployment | Runs anywhere. No mandatory egress to a vendor cloud. |
| Open-format pluggability | Native JSON, Grafana, Superset, Metabase, Sigma rules. |

Snowflake remains the right choice when your team already standardizes on a
warehouse. AWS Security Lake remains right when OCSF Parquet on S3 is the
contract. ClickHouse wins when you want the **operator-owned, sovereign,
low-latency** lake — which is the modal need for an AI-era security team.

## Step 1 — Provision the lake (one shot)

Apply the DDL pack with an operator role. The downstream skills hold no DDL
rights:

```bash
cd packs/clickhouse

for f in ddl/*.sql materialized-views/*.sql; do
  clickhouse-client --multiquery < "$f"
done
```

This creates `security.events_sink`, `security.findings_sink`,
`security.evidence_sink`, `security.audit_sink`, the three rollup
materialized views, and the per-table row policy that isolates by
`cloud.account.uid`.

Grant the **runtime** role only:

```sql
GRANT SELECT, INSERT ON security.events_sink     TO agent_bom_runtime;
GRANT SELECT, INSERT ON security.findings_sink   TO agent_bom_runtime;
GRANT SELECT, INSERT ON security.evidence_sink   TO agent_bom_runtime;
GRANT SELECT, INSERT ON security.audit_sink      TO agent_bom_runtime;
GRANT SELECT          ON security.findings_by_rule_hourly       TO agent_bom_runtime;
GRANT SELECT          ON security.events_by_class_daily         TO agent_bom_runtime;
GRANT SELECT          ON security.remediations_by_outcome_daily TO agent_bom_runtime;
```

Note: `INSERT` only — no `CREATE`, `ALTER`, `DROP`, `OPTIMIZE`, or `TRUNCATE`.

## Step 2 — Wire ingest into the lake

Every shipped `ingest-*` skill emits OCSF JSONL on stdout. Pipe directly into
`sink-clickhouse-jsonl`:

```bash
aws cloudtrail lookup-events --max-results 1000 \
  | python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py \
  | python skills/output/sink-clickhouse-jsonl/src/sink.py \
      --table security.events_sink \
      --apply
```

The same shape works for every other ingest skill:

| Vendor | Ingest skill | Lake table |
|---|---|---|
| AWS CloudTrail | `ingest-cloudtrail-ocsf` | `security.events_sink` |
| AWS VPC Flow Logs | `ingest-vpc-flow-logs-ocsf` | `security.events_sink` |
| AWS GuardDuty | `ingest-guardduty-ocsf` | `security.findings_sink` |
| AWS Security Hub | `ingest-security-hub-ocsf` | `security.findings_sink` |
| GCP audit | `ingest-gcp-audit-ocsf` | `security.events_sink` |
| GCP SCC | `ingest-gcp-scc-ocsf` | `security.findings_sink` |
| Azure activity | `ingest-azure-activity-ocsf` | `security.events_sink` |
| Azure Defender | `ingest-azure-defender-for-cloud-ocsf` | `security.findings_sink` |
| Entra | `ingest-entra-directory-audit-ocsf` | `security.events_sink` |
| K8s audit | `ingest-k8s-audit-ocsf` | `security.events_sink` |
| Okta | `ingest-okta-system-log-ocsf` | `security.events_sink` |
| Workspace | `ingest-google-workspace-login-ocsf` | `security.events_sink` |
| MCP proxy | `ingest-mcp-proxy-ocsf` | `security.events_sink` |
| GitHub | `ingest-github-audit-log-ocsf` | `security.events_sink` |
| Slack | `ingest-slack-audit-ocsf` | `security.events_sink` |

## Step 3 — Detect from the lake (replay or live)

The read-side skill is `source-clickhouse-query`. It enforces a strict
read-only SQL allowlist (`SELECT`, `WITH`, `SHOW`, `DESCRIBE`) — no comments,
no session controls, no admin verbs. Compose it with any `detect-*` skill:

```bash
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "$(cat packs/clickhouse/queries/backfill_detection_window.sql)" \
  | jq -c '.payload | fromjson' \
  | python skills/detection/detect-lateral-movement/src/detect.py \
  | python skills/output/sink-clickhouse-jsonl/src/sink.py \
      --table security.findings_sink \
      --apply
```

This is the moment ClickHouse stops being a sink and starts being a **lake**:
you can ship a new detection rule on Monday and have it backfilled against
a week of normalized OCSF events by Monday afternoon.

## Step 4 — Close the loop with view / remediate

Replay findings out of the lake into operator-facing views:

```bash
# SARIF for audit handoff
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "$(cat packs/clickhouse/queries/replay_findings_last_day.sql)" \
  | jq -c '.payload | fromjson' \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py

# Mermaid attack-flow for incident review
python skills/ingestion/source-clickhouse-query/src/ingest.py \
  --query "$(cat packs/clickhouse/queries/replay_findings_last_day.sql)" \
  | jq -c '.payload | fromjson' \
  | python skills/view/convert-ocsf-to-mermaid-attack-flow/src/convert.py
```

Every HITL-gated `remediate-*` skill also dual-writes its audit chain back
into `security.audit_sink`, so the lake captures **what was decided** as well
as **what fired**.

## What it buys an AI agent

The ClickHouse lake is what makes the skill set agent-native, not just
agent-callable:

1. **Stateless detectors, stateful lake.** The skills never carry per-tenant
   state. Replays converge because uids are content-addressed.
2. **MCP-callable.** Both `sink-clickhouse-jsonl` and
   `source-clickhouse-query` are auto-registered as MCP tools — Claude,
   Cursor, Codex, Cortex can pipe through them without bespoke wiring.
3. **Bounded SQL surface.** The source skill enforces a read-only allowlist
   before the agent's SQL ever touches the wire. There is no "the LLM wrote
   a DROP TABLE" failure mode.
4. **Sub-second triage.** The materialized views answer "top rules today",
   "ingest volume by class", and "remediation outcome counts" in
   milliseconds, freeing the agent's context budget for actual judgment.

## Non-goals

- This doc does not turn the repo into a SIEM. The lake replaces the SIEM's
  **storage tier**, not its **operator UX**. Pair with Grafana or Superset.
- The sink and source skills do not perform encryption-at-rest or
  TLS-in-flight on their own. Both are properties of the ClickHouse cluster
  the operator provisions.
- ClickHouse Cloud row-level policies are evaluated at query time. For
  multi-region tenancy enforce a per-region cluster, not just a row policy.

## Related

- [`packs/clickhouse/README.md`](../packs/clickhouse/README.md) — pack contents and CLI run-through
- [`SINK_CONTRACT.md`](SINK_CONTRACT.md) — what every sink must do, and what it must not
- [`AGENT_DATA_LAKE_FLOW.md`](AGENT_DATA_LAKE_FLOW.md) — the three repo-supported lake flows
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — the 7-layer skill model behind the diagram
