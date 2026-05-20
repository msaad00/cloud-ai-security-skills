-- Events sink — normalized OCSF events from any `ingest-*` skill.
--
-- This is the hot tier of the security data lake. Detection skills replay
-- from here through `source-clickhouse-query`. Schema matches the sink
-- contract: one event per row, JSON payload, content-addressed event_uid.
--
-- Partitioning: daily — high-cardinality CloudTrail / VPC flow ingest pushes
--               volumes that warrant finer granularity than findings.
-- Ordering   : (schema_mode, event_uid). Replay-by-uid stays cheap; the
--               secondary skip indices speed up time-window scans.
-- Retention  : 90 days hot. Cold copies should be tee'd to S3 via the
--               sink-s3-jsonl skill at ingest time.

CREATE TABLE IF NOT EXISTS security.events_sink
(
    payload      String                CODEC(ZSTD(3)),
    schema_mode  LowCardinality(String),
    event_uid    String,
    finding_uid  String,
    ingested_at  DateTime DEFAULT now() CODEC(DoubleDelta, LZ4),
    INDEX        idx_ingested_at ingested_at TYPE minmax GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ingested_at)
ORDER BY (schema_mode, event_uid)
TTL ingested_at + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
