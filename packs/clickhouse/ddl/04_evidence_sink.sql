-- Evidence sink — control-evidence and posture artifacts.
--
-- Consumed by:
--   discover-control-evidence
--   discover-cloud-control-evidence
--   cspm-*-cis-benchmark (when materializing compliance evidence)
--
-- Compliance auditors read this table directly. Keep it append-only and
-- keep the retention long (compliance frameworks typically demand 7 years).

CREATE TABLE IF NOT EXISTS security.evidence_sink
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
TTL ingested_at + INTERVAL 2557 DAY  -- ~7 years for SOC 2 / PCI / HIPAA evidence holds
SETTINGS index_granularity = 8192;
