-- Audit sink — remediation + MCP audit trail.
--
-- Consumed by:
--   remediate-*  (every HITL-gated remediation skill dual-audits here)
--   mcp-server   (every dispatched tool call writes an audit row)
--
-- Auditors need millisecond timestamps and tamper-evident retention. The
-- table is partitioned by month for cheap dropping of pre-retention windows
-- only after a legal hold release; ClickHouse TTL is intentionally not set.
-- Operators apply retention via approved process, not by table default.

CREATE TABLE IF NOT EXISTS security.audit_sink
(
    payload      String                CODEC(ZSTD(3)),
    schema_mode  LowCardinality(String),
    event_uid    String,
    finding_uid  String,
    ingested_at  DateTime64(3, 'UTC')  DEFAULT now64(3) CODEC(DoubleDelta, LZ4)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ingested_at)
ORDER BY (schema_mode, event_uid)
SETTINGS index_granularity = 8192;
