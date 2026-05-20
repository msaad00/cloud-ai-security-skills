-- Materialized view: remediation outcomes per day.
--
-- Closed-loop telemetry: how many remediations applied, dry-ran, failed, or
-- got denied by HITL today. Pair this view with a Grafana panel + a daily
-- digest email so the security team sees drift without opening the lake.

CREATE TABLE IF NOT EXISTS security.remediations_by_outcome_daily
(
    bucket_day        Date CODEC(DoubleDelta, LZ4),
    skill_name        LowCardinality(String),
    remediation_state LowCardinality(String),
    outcome_count     UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(bucket_day)
ORDER BY (bucket_day, skill_name, remediation_state);

CREATE MATERIALIZED VIEW IF NOT EXISTS security.remediations_by_outcome_daily_mv
TO security.remediations_by_outcome_daily
AS
SELECT
    toDate(ingested_at)                                  AS bucket_day,
    JSONExtractString(payload, 'skill')                  AS skill_name,
    JSONExtractString(payload, 'remediation_status')     AS remediation_state,
    count()                                              AS outcome_count
FROM security.audit_sink
WHERE JSONExtractString(payload, 'record_type') = 'remediation_audit'
GROUP BY bucket_day, skill_name, remediation_state;
