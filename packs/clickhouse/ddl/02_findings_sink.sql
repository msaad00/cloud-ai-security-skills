-- Findings sink — OCSF Detection Finding (2004) and repo-native finding rows.
--
-- Append-only. The `sink-clickhouse-jsonl` skill is the only writer; it
-- inserts (payload, schema_mode, event_uid, finding_uid) and lets
-- `ingested_at` default. Operators run DDL; the sink never does.
--
-- Partitioning: monthly by ingest day. Cheap to drop a whole month.
-- Ordering : (schema_mode, finding_uid, event_uid). Joins and dedupe hit
--            the primary index. Replays converge because finding_uid is
--            content-addressable (det-<rule>-<short(semantic_key)>).
-- Retention : 365 days, lifecycle managed by ClickHouse TTL.

CREATE TABLE IF NOT EXISTS security.findings_sink
(
    payload      String                CODEC(ZSTD(3)),
    schema_mode  LowCardinality(String),
    event_uid    String,
    finding_uid  String,
    ingested_at  DateTime DEFAULT now() CODEC(DoubleDelta, LZ4)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ingested_at)
ORDER BY (schema_mode, finding_uid, event_uid)
TTL ingested_at + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;
