# Examples — IAM Departures Remediation

## Quick Start: Deploy with CloudFormation

```bash
# 1. Deploy the stack to your Security OU account
aws cloudformation deploy \
  --template-file infra/cloudformation.yaml \
  --stack-name iam-departures-remediation \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    RemediationBucket=my-security-remediation-bucket \
    KmsKeyArn=arn:aws:kms:us-east-1:111111111111:key/abc-123 \
    OrgId=o-abc123def4 \
  --region us-east-1

# 2. Deploy the cross-account role to all member accounts via StackSets
aws cloudformation create-stack-set \
  --stack-set-name iam-departures-cross-account \
  --template-body file://infra/cross_account_stackset.yaml \
  --parameters \
    ParameterKey=SecurityAccountId,ParameterValue=111111111111 \
    ParameterKey=OrgId,ParameterValue=o-abc123def4 \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM
```

## Example: Run Reconciler with Snowflake Source

```bash
# Set Snowflake credentials
export SNOWFLAKE_ACCOUNT=myorg-myaccount
export SNOWFLAKE_USER=svc_iam_reconciler
# Retrieve password from your secrets manager (Secrets Manager, Vault, etc.)
# Do NOT hardcode credentials. Example using AWS Secrets Manager CLI:
#   aws secretsmanager get-secret-value --secret-id iam-reconciler/snowflake
export SNOWFLAKE_PASSWORD="<from-secrets-manager>"

# Set AWS config
export AWS_ACCOUNT_ID=111111111111
export IAM_REMEDIATION_BUCKET=my-security-remediation-bucket

# Run reconciler
python -m reconciler.sources --source snowflake
```

## Example: Run Reconciler with Snowflake Storage Integration

```bash
# No credentials needed — uses Storage Integration + IAM role
export SNOWFLAKE_ACCOUNT=myorg-myaccount
export SNOWFLAKE_STORAGE_INTEGRATION=iam_departures_integration

# Snowflake unloads data to S3, reconciler reads from there
python -m reconciler.sources --source snowflake --use-storage-integration
```

## Example: Test Locally with Mock Data

```bash
# Run the test suite
cd skills/remediation/iam-departures-remediation
python -m pytest tests/ -v

# Test specific rehire scenarios
python -m pytest tests/test_reconciler.py -k "test_rehire" -v

# Test Lambda parser with a sample manifest
python -m pytest tests/test_parser_lambda.py -v

# Test worker with mocked IAM calls
python -m pytest tests/test_worker_lambda.py -v
```

## Example: Test Trigger via S3 and EventBridge

```bash
# Upload a manifest to the bucket and let EventBridge start the Step Function
aws s3 cp sample-manifest.json \
  s3://my-security-remediation-bucket/departures/2026-03-01.json
```

This is the preferred manual test path because it exercises the same event-driven
entrypoint used in production instead of bypassing EventBridge.

## Example: Query Audit Records

```sql
-- DynamoDB (via PartiQL)
SELECT * FROM "iam-remediation-audit"
WHERE remediated_at > '2026-03-01'
ORDER BY remediated_at DESC;

-- Snowflake (after ingest-back)
SELECT
    iam_username,
    target_account_id,
    remediation_actions,
    remediated_at,
    invoked_by,
    approved_by,
    approval_ticket,
    lambda_request_id
FROM security_db.iam.remediation_audit
WHERE remediated_at >= DATEADD(day, -7, CURRENT_DATE())
ORDER BY remediated_at DESC;
```

## Example: Verify Cross-Account Role

```bash
# From the Security OU account, test AssumeRole into a target account
aws sts assume-role \
  --role-arn arn:aws:iam::222222222222:role/iam-remediation-role \
  --role-session-name test-remediation \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
  --output text

# Verify IAM permissions in the target account
aws iam get-user --user-name test-departed-user
```
