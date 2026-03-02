-- Snowflake Storage Integration for IAM Departures Remediation
--
-- This creates a Storage Integration that allows Snowflake to read/write
-- to the remediation S3 bucket without storing AWS credentials in Snowflake.
--
-- Prerequisites:
--   1. AWS IAM role: iam-departures-snowflake-role (see reference.md)
--   2. S3 bucket: ${IAM_REMEDIATION_BUCKET} with EventBridge notifications ON
--
-- After running this, execute DESC INTEGRATION to get:
--   - STORAGE_AWS_IAM_USER_ARN  → put in IAM trust policy
--   - STORAGE_AWS_EXTERNAL_ID   → put in IAM trust policy condition
--
-- Reference: https://docs.snowflake.com/en/sql-reference/sql/create-storage-integration

-- ═══════════════════════════════════════════════════════════════
-- Step 1: Create the Storage Integration (ACCOUNTADMIN required)
-- ═══════════════════════════════════════════════════════════════

USE ROLE ACCOUNTADMIN;

CREATE OR REPLACE STORAGE INTEGRATION iam_departures_integration
  TYPE = EXTERNAL_STAGE
  STORAGE_PROVIDER = 'S3'
  ENABLED = TRUE
  STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::<SECURITY_ACCOUNT_ID>:role/iam-departures-snowflake-role'
  STORAGE_ALLOWED_LOCATIONS = (
    's3://<IAM_REMEDIATION_BUCKET>/snowflake-export/',
    's3://<IAM_REMEDIATION_BUCKET>/departures/'
  )
  STORAGE_BLOCKED_LOCATIONS = (
    's3://<IAM_REMEDIATION_BUCKET>/departures/audit/'
  )
  COMMENT = 'IAM departures remediation — read HR data, write manifests';

-- Get the Snowflake-generated IAM user ARN and external ID
-- These MUST be added to the AWS IAM trust policy for the role
DESC INTEGRATION iam_departures_integration;

-- ═══════════════════════════════════════════════════════════════
-- Step 2: Create External Stage
-- ═══════════════════════════════════════════════════════════════

USE ROLE SYSADMIN;

CREATE OR REPLACE STAGE security_db.iam.departures_stage
  STORAGE_INTEGRATION = iam_departures_integration
  URL = 's3://<IAM_REMEDIATION_BUCKET>/snowflake-export/'
  FILE_FORMAT = (TYPE = JSON, STRIP_OUTER_ARRAY = TRUE)
  COMMENT = 'External stage for IAM departures data exchange';

-- ═══════════════════════════════════════════════════════════════
-- Step 3: Unload IAM inventory for reconciler consumption
-- ═══════════════════════════════════════════════════════════════

-- This is run by a Snowflake Task (daily) to export joined HR + IAM data
-- to S3 where the reconciler can pick it up without direct Snowflake access.

CREATE OR REPLACE TASK security_db.iam.export_departures_task
  WAREHOUSE = security_wh
  SCHEDULE = 'USING CRON 0 6 * * * America/Los_Angeles'
  COMMENT = 'Daily export of departed employee IAM records to S3 for remediation'
AS
  COPY INTO @security_db.iam.departures_stage/departed_employees
  FROM (
    SELECT
      w.email_address         AS email,
      i.account_id            AS recipient_account_id,
      i.iam_username,
      i.created_at            AS iam_created_at,
      w.termination_date      AS terminated_at,
      w.rehire_date,
      i.last_used_at          AS iam_last_used_at,
      i.is_deleted            AS iam_deleted,
      i.deleted_at            AS iam_deleted_at
    FROM hr_db.workday.employees w
    JOIN security_db.iam.iam_users i
      ON LOWER(w.email_address) = LOWER(i.email)
    WHERE w.termination_date IS NOT NULL
      AND w.termination_date <= CURRENT_DATE()
  )
  FILE_FORMAT = (TYPE = JSON)
  OVERWRITE = TRUE
  SINGLE = TRUE
  HEADER = TRUE;

-- Enable the task
ALTER TASK security_db.iam.export_departures_task RESUME;

-- ═══════════════════════════════════════════════════════════════
-- Step 4: Ingest audit records back from DynamoDB/S3
-- ═══════════════════════════════════════════════════════════════

-- External stage for reading audit logs written by Lambda
CREATE OR REPLACE STAGE security_db.iam.audit_stage
  STORAGE_INTEGRATION = iam_departures_integration
  URL = 's3://<IAM_REMEDIATION_BUCKET>/departures/audit/'
  FILE_FORMAT = (TYPE = JSON)
  COMMENT = 'External stage for reading remediation audit logs';

-- Table for storing ingested audit records
CREATE TABLE IF NOT EXISTS security_db.iam.remediation_audit (
  iam_username        VARCHAR(255)   NOT NULL,
  target_account_id   VARCHAR(12)    NOT NULL,
  email               VARCHAR(255),
  terminated_at       TIMESTAMP_TZ,
  remediated_at       TIMESTAMP_TZ   NOT NULL,
  remediation_actions VARIANT,       -- JSON array of actions taken
  steps_completed     INTEGER,
  steps_failed        INTEGER,
  lambda_request_id   VARCHAR(255),
  execution_arn       VARCHAR(512),
  ingested_at         TIMESTAMP_TZ   DEFAULT CURRENT_TIMESTAMP()
);

-- Task to ingest new audit records (runs hourly)
CREATE OR REPLACE TASK security_db.iam.ingest_audit_task
  WAREHOUSE = security_wh
  SCHEDULE = 'USING CRON 0 * * * * America/Los_Angeles'
  COMMENT = 'Hourly ingest of remediation audit records from S3'
AS
  COPY INTO security_db.iam.remediation_audit (
    iam_username, target_account_id, email, terminated_at,
    remediated_at, remediation_actions, steps_completed,
    steps_failed, lambda_request_id, execution_arn
  )
  FROM (
    SELECT
      $1:iam_username::VARCHAR,
      $1:target_account_id::VARCHAR,
      $1:email::VARCHAR,
      $1:terminated_at::TIMESTAMP_TZ,
      $1:remediated_at::TIMESTAMP_TZ,
      $1:actions,
      $1:steps_completed::INTEGER,
      $1:steps_failed::INTEGER,
      $1:lambda_request_id::VARCHAR,
      $1:execution_arn::VARCHAR
    FROM @security_db.iam.audit_stage
  )
  FILE_FORMAT = (TYPE = JSON)
  ON_ERROR = CONTINUE;

ALTER TASK security_db.iam.ingest_audit_task RESUME;

-- ═══════════════════════════════════════════════════════════════
-- Step 5: Grant minimum required privileges
-- ═══════════════════════════════════════════════════════════════

-- Service role for the reconciler (read HR + IAM, write to stage)
CREATE ROLE IF NOT EXISTS iam_reconciler_role;
GRANT USAGE ON DATABASE hr_db TO ROLE iam_reconciler_role;
GRANT USAGE ON SCHEMA hr_db.workday TO ROLE iam_reconciler_role;
GRANT SELECT ON TABLE hr_db.workday.employees TO ROLE iam_reconciler_role;
GRANT USAGE ON DATABASE security_db TO ROLE iam_reconciler_role;
GRANT USAGE ON SCHEMA security_db.iam TO ROLE iam_reconciler_role;
GRANT SELECT ON TABLE security_db.iam.iam_users TO ROLE iam_reconciler_role;
GRANT USAGE ON INTEGRATION iam_departures_integration TO ROLE iam_reconciler_role;
GRANT READ, WRITE ON STAGE security_db.iam.departures_stage TO ROLE iam_reconciler_role;

-- Service user for automated access
CREATE USER IF NOT EXISTS svc_iam_reconciler
  DEFAULT_ROLE = iam_reconciler_role
  MUST_CHANGE_PASSWORD = FALSE
  COMMENT = 'Service account for IAM departures reconciliation';
GRANT ROLE iam_reconciler_role TO USER svc_iam_reconciler;
