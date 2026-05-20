-- Replay every finding ingested in the last 24 hours.
--
-- Pipe through `source-clickhouse-query` into a view-* skill to re-render the
-- same findings as SARIF or Mermaid without re-running detection.

SELECT payload
FROM security.findings_sink
WHERE ingested_at >= now() - INTERVAL 1 DAY
  AND schema_mode = 'ocsf'
ORDER BY ingested_at DESC
