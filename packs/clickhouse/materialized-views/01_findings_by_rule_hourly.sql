-- Materialized view: findings volume per rule per hour.
--
-- Powers the operator's at-a-glance "what fired last hour" dashboard and the
-- agent's quick triage. Reading the rolled-up table is O(rules x hours),
-- materially cheaper than rescanning `findings_sink`.
--
-- Why a SummingMergeTree:
--   This is a volume counter over append-only rows. SummingMergeTree sums
--   counters with the same sorting key during part merges. It does not
--   de-duplicate repeated raw inserts; use UID-aware queries over
--   `findings_sink` when unique finding cardinality matters.

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
