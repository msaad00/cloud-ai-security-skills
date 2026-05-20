-- Materialized view: ingest volume per OCSF class per day.
--
-- Lets the operator confirm that every ingest-* skill is still landing rows
-- in the lake, and lets the agent answer "how much ingest did you get
-- yesterday?" without rescanning the raw events table.

CREATE TABLE IF NOT EXISTS security.events_by_class_daily
(
    bucket_day   Date    CODEC(DoubleDelta, LZ4),
    class_uid    UInt32,
    schema_mode  LowCardinality(String),
    event_count  UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(bucket_day)
ORDER BY (bucket_day, class_uid, schema_mode);

CREATE MATERIALIZED VIEW IF NOT EXISTS security.events_by_class_daily_mv
TO security.events_by_class_daily
AS
SELECT
    toDate(ingested_at)                                        AS bucket_day,
    toUInt32OrZero(JSONExtractString(payload, 'class_uid'))    AS class_uid,
    schema_mode                                                AS schema_mode,
    count()                                                    AS event_count
FROM security.events_sink
GROUP BY bucket_day, class_uid, schema_mode;
