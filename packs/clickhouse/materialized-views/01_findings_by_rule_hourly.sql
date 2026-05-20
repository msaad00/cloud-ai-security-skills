-- Materialized view: findings volume per rule per hour.
--
-- Powers the operator's at-a-glance "what fired last hour" Grafana panel and
-- the agent's quick triage. Reading the rolled-up table is O(rules x hours),
-- a couple of orders of magnitude cheaper than rescanning `findings_sink`.
--
-- Why a SummingMergeTree:
--   The same finding_uid is content-addressable, so an idempotent re-ingest
--   inserts the same row twice; SummingMergeTree collapses duplicates by
--   summing finding_count when parts merge. That keeps the metric correct
--   under replays.

CREATE TABLE IF NOT EXISTS security.findings_by_rule_hourly
(
    bucket_hour   DateTime CODEC(DoubleDelta, LZ4),
    rule_uid      LowCardinality(String),
    severity      LowCardinality(String),
    schema_mode   LowCardinality(String),
    finding_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(bucket_hour)
ORDER BY (bucket_hour, rule_uid, severity, schema_mode);

CREATE MATERIALIZED VIEW IF NOT EXISTS security.findings_by_rule_hourly_mv
TO security.findings_by_rule_hourly
AS
SELECT
    toStartOfHour(ingested_at)                              AS bucket_hour,
    JSONExtractString(payload, 'finding_info', 'uid')       AS rule_uid,
    JSONExtractString(payload, 'severity')                  AS severity,
    schema_mode                                             AS schema_mode,
    count()                                                 AS finding_count
FROM security.findings_sink
GROUP BY bucket_hour, rule_uid, severity, schema_mode;
