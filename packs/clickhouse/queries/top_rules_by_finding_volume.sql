-- Top firing rules in the last 7 days, by finding volume.
--
-- Reads the rolled-up materialized view — millisecond response on a year of
-- findings. Useful for "which rule is noisiest right now" triage.

SELECT
    rule_uid,
    severity,
    sum(finding_count) AS findings
FROM security.findings_by_rule_hourly
WHERE bucket_hour >= now() - INTERVAL 7 DAY
GROUP BY rule_uid, severity
ORDER BY findings DESC
LIMIT 25
