-- Row-level policies — multi-tenant isolation by cloud account.
--
-- ClickHouse evaluates the JSON predicate at query time via JSONExtractString.
-- Operators provision a per-tenant role whose `tenant_uid` claim feeds into a
-- session setting (`SET tenant_uid = '…'`) before the policy fires.
--
-- The skills never set this themselves; the platform manager that brokers the
-- connection does. The skill registry remains tenant-agnostic.

CREATE ROW POLICY IF NOT EXISTS findings_tenant_isolation
    ON security.findings_sink
    USING JSONExtractString(payload, 'cloud', 'account', 'uid') = getSetting('tenant_uid')
    TO ALL EXCEPT default;

CREATE ROW POLICY IF NOT EXISTS events_tenant_isolation
    ON security.events_sink
    USING JSONExtractString(payload, 'cloud', 'account', 'uid') = getSetting('tenant_uid')
    TO ALL EXCEPT default;

CREATE ROW POLICY IF NOT EXISTS evidence_tenant_isolation
    ON security.evidence_sink
    USING JSONExtractString(payload, 'cloud', 'account', 'uid') = getSetting('tenant_uid')
    TO ALL EXCEPT default;
