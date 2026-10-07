# aws-s3-sqs-detect

Reference persistent runner template for continuous ingest → detect pipelines on
AWS. The template attaches to an existing source bucket and keeps the queue,
dedupe table, and alert path inside the stack.

## What it does

```
S3 object create
  -> ingest Lambda
  -> SQS queue
  -> detect Lambda
  -> DynamoDB dedupe
  -> SNS fan-out
```

The runner keeps state and side effects at the edges:
- S3 is the raw object source
- SQS provides durable decoupling
- DynamoDB stores replay-safe dedupe keys
- SNS distributes new findings downstream

The skills remain unchanged and stateless.

## When to use it

- You want a repo-owned example of a persistent execution path beyond IAM departures
- You need a minimal AWS pattern for continuous ingest → detect with replay safety
- You want to wire any compatible `ingest-*` and `detect-*` skill pair into a
  queue-driven loop

## What it does not do

- It is not a generic sink framework for every cloud or SIEM
- It does not package Lambda zip artifacts for you
- It does not hardcode a specific skill family, sink vendor, or storage format

## Required environment variables

### Ingest Lambda

- `INGEST_SKILL_CMD`
  Example: `python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py` (OCSF, the default — detect skills consume OCSF)
- `DETECT_QUEUE_URL`

### Detect Lambda

- `DETECT_SKILL_CMD`
  Example: `python skills/detection/detect-aws-open-security-group/src/detect.py`
- `DEDUPE_TABLE`
- `DEDUPE_TTL_DAYS` (optional, default 30, range 1-365). Controls how long dedupe rows live before DynamoDB TTL expires them.
- `SNS_TOPIC_ARN`

## Packaging model

The CloudFormation template expects:
- an existing source bucket name
- one zip for the ingest handler
- one zip for the detect handler

That keeps the template deployable without assuming SAM or an external build
system.

## Security model

- no shell invocation; skill commands are tokenized with `shlex.split`
- `subprocess.run(..., shell=False)` only
- DynamoDB conditional writes prevent duplicate publish on replay
- detect-side downstream fan-out uses SNS `publish_batch` in batches of up to
  `10` findings per API call instead of one publish call per finding
- DynamoDB TTL is enabled with an `expires_at` attribute on every new dedupe
  row. The `DedupeTtlDays` CloudFormation parameter (default 30, range 1-365)
  flows into the detect Lambda as `DEDUPE_TTL_DAYS` and controls how long a
  UID stays suppressed before DynamoDB deletes the row and a recurrence is
  allowed to re-fire. Rows written before TTL was enabled are not backfilled
  and will remain until they are overwritten or removed manually.
- SNS only sees deduped findings
- operators should scope the Lambda roles to the specific source bucket, queue,
  topic, and table ARNs in their environment

## Live Deploy Verification Status

Real deploy proof captured on 2026-10-07 (AWS `us-east-2`, Lambda
`python3.11`, runtime version `python:3.11.mainlinev2.v43`), following the
[Prepared Walkthrough](#prepared-walkthrough) below with
`ingest-cloudtrail-ocsf` → `detect-aws-open-security-group` and the golden
fixture `skills/detection-engineering/golden/aws_open_security_group_raw.jsonl`.
The stack, bucket, and Lambda log groups were deleted afterwards and verified
not-found. Account ID is redacted.

| Step | Evidence |
|---|---|
| package | ingest zip 35,443 B, detect zip 37,455 B (handler at root + `skills/_shared` + one skill dir) |
| deploy | `aws cloudformation deploy` → `CREATE_COMPLETE` for all 10 resources in ~2 min |
| bind | `put-bucket-notification-configuration` → `s3:ObjectCreated:*`, prefix `incoming/` |
| trigger | object `incoming/run1/aws_open_security_group_raw.jsonl` uploaded 04:10:28Z; ingest Lambda `START` 04:10:30Z, `Duration: 4462 ms`, no error |
| ingest → queue | detect queue `NumberOfMessagesSent` = 1 (one OCSF line) |
| detect | detect Lambda (SQS event source mapping) `START` 04:10:35Z, `Duration: 4412 ms`, `Errors` = 0; bare `python` resolves on the `python3.11` runtime |
| dedupe | DynamoDB item `pk=asg-2a9136fc748f620b`, `payload_sha256=e222266d…4ca5` (byte-identical to the golden `aws_open_security_group_pipe_findings.ocsf.jsonl` line, MITRE T1190), `expires_at` = seen_at + 30 d |
| publish | SNS `NumberOfMessagesPublished` = 1 (SampleCount 1) |
| redelivery | same object re-uploaded as `incoming/run2-redeliver/…` 04:11:40Z → ingest ran, 2nd SQS message, detect ran 1589 ms with 0 errors; DynamoDB still holds exactly 1 item with the original `seen_at`; SNS total stays 1 |

Operational notes from the live run:

- An object uploaded within about a minute of `put-bucket-notification-configuration`
  returned did not invoke the Lambda; uploads ~6 min later fired within 2 s.
  After binding, confirm with one upload (or a short wait) before relying on
  the trigger.
- Lambda creates `/aws/lambda/<function>` log groups outside the stack;
  delete them separately on teardown.

## First Event Proof Checklist

When capturing the live walkthrough for this runner, record:

1. the exact CloudFormation deploy command and parameters
2. the source bucket notification binding
3. one uploaded object that triggers the ingest path
4. evidence that:
   - ingest Lambda ran
   - an SQS detect message was created
   - detect Lambda ran
   - a DynamoDB dedupe row was written
   - an SNS publish succeeded

## Prepared Walkthrough

### 0. Package the handlers

Each Lambda zip carries its handler at the zip root plus `skills/_shared` and
the one skill directory it runs (skills resolve `skills._shared` relative to
their own path, so the repo layout must be preserved; no `__init__.py` files
are needed). `boto3` comes from the Lambda runtime. From the repo root:

```bash
zip -qr -X /tmp/ingest.zip skills/_shared skills/ingestion/ingest-cloudtrail-ocsf/src -x '*__pycache__*'
zip -qr -X /tmp/detect.zip skills/_shared skills/detection/detect-aws-open-security-group/src -x '*__pycache__*'
(cd runners/aws-s3-sqs-detect/src && zip -q -X /tmp/ingest.zip ingest_handler.py && zip -q -X /tmp/detect.zip detect_handler.py)
aws s3 cp /tmp/ingest.zip s3://<artifacts-bucket>/code/ingest.zip
aws s3 cp /tmp/detect.zip s3://<artifacts-bucket>/code/detect.zip
```

### 1. Deploy the stack

The ingest skill must emit OCSF (its default): `detect-*` skills consume OCSF
and skip native-format records (with only a stderr warning), so `--output-format native` on the
ingest side produces zero findings.

```bash
aws cloudformation deploy \
  --template-file runners/aws-s3-sqs-detect/template.yaml \
  --stack-name cloud-security-runner-aws \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
      SourceBucketName=<existing-source-bucket> \
      IngestCodeBucket=<artifacts-bucket> \
      IngestCodeKey=code/ingest.zip \
      DetectCodeBucket=<artifacts-bucket> \
      DetectCodeKey=code/detect.zip \
      "IngestSkillCommand=python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py" \
      "DetectSkillCommand=python skills/detection/detect-aws-open-security-group/src/detect.py"
```

### 2. Bind the source event

The template grants S3 permission to invoke the ingest Lambda but does not own
the (pre-existing) source bucket, so bind the notification yourself. This
replaces the bucket's whole notification configuration; merge with any
existing entries first (`aws s3api get-bucket-notification-configuration`).

```bash
INGEST_ARN=$(aws cloudformation describe-stack-resource \
  --stack-name cloud-security-runner-aws --logical-resource-id IngestFunction \
  --query StackResourceDetail.PhysicalResourceId --output text \
  | xargs -I{} aws lambda get-function --function-name {} \
      --query Configuration.FunctionArn --output text)

aws s3api put-bucket-notification-configuration \
  --bucket <existing-source-bucket> \
  --notification-configuration '{
    "LambdaFunctionConfigurations": [{
      "Id": "cloud-security-runner-ingest",
      "LambdaFunctionArn": "'"$INGEST_ARN"'",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "incoming/"}]}}
    }]
  }'
```

### 3. Send one real event

```bash
aws s3 cp skills/detection-engineering/golden/aws_open_security_group_raw.jsonl \
  s3://<existing-source-bucket>/incoming/aws_open_security_group_raw.jsonl
```

### 4. Capture proof

- CloudWatch log lines showing the ingest Lambda invocation
- an SQS message in the detect queue
- CloudWatch log lines showing the detect Lambda invocation
- a DynamoDB item in the dedupe table with `pk`, `payload_sha256`, and `expires_at`
- an SNS message or subscriber receipt proving the downstream publish
