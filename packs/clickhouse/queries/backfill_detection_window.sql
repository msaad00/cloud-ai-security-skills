-- Backfill a detection over a historical OCSF event window.
--
-- Use case: a new `detect-*` rule shipped. Replay last 7 days of normalized
-- API Activity (6003) + Network Activity (4001) through the new detector
-- without re-ingesting from the vendor.
--
-- Compose:
--   source-clickhouse-query --query "$(cat backfill_detection_window.sql)" \
--     | jq -c '.payload | fromjson' \
--     | python skills/detection/detect-lateral-movement/src/detect.py \
--     | python skills/output/sink-clickhouse-jsonl/src/sink.py \
--         --table security.findings_sink --apply

SELECT payload
FROM security.events_sink
WHERE ingested_at >= now() - INTERVAL 7 DAY
  AND schema_mode = 'ocsf'
  AND toUInt32OrZero(JSONExtractString(payload, 'class_uid')) IN (6003, 4001)
ORDER BY ingested_at ASC
