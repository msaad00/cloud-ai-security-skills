# IAM Departures Remediation — Terraform Module
#
# Equivalent to cloudformation.yaml. Deploys the full pipeline:
# S3 bucket, KMS, DynamoDB audit table, Lambda functions,
# Step Function, EventBridge rule, and all IAM roles.
#
# MITRE ATT&CK: T1078.004, T1098.001, T1087.004, T1531, T1552
# NIST CSF 2.0: PR.AC-1, PR.AC-4, DE.CM-3, RS.MI-2
# CIS Controls v8: 5.3, 6.1, 6.2, 6.5

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# ── Variables ──────────────────────────────────────────────────

variable "remediation_bucket" {
  description = "S3 bucket name for manifests and audit logs"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.remediation_bucket))
    error_message = "Bucket name must be valid S3 naming"
  }
}

variable "kms_key_arn" {
  description = "KMS key ARN for S3 encryption"
  type        = string
  validation {
    condition     = can(regex("^arn:aws:kms:", var.kms_key_arn))
    error_message = "Must be a valid KMS key ARN"
  }
}

variable "org_id" {
  description = "AWS Organizations ID (e.g., o-abc123def4)"
  type        = string
  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.org_id))
    error_message = "Must be a valid AWS Organization ID"
  }
}

variable "cross_account_role_name" {
  description = "Name of the cross-account role deployed to target accounts"
  type        = string
  default     = "iam-remediation-role"
}

variable "audit_dynamodb_table" {
  description = "DynamoDB table name for audit records"
  type        = string
  default     = "iam-remediation-audit"
}

variable "grace_period_days" {
  description = "Days after termination before remediation fires"
  type        = number
  default     = 7
  validation {
    condition     = var.grace_period_days >= 0 && var.grace_period_days <= 90
    error_message = "Grace period must be 0-90 days"
  }
}

variable "parser_code_s3_key" {
  description = "S3 key for Lambda parser deployment package"
  type        = string
  default     = "lambda/iam-departures-parser.zip"
}

variable "worker_code_s3_key" {
  description = "S3 key for Lambda worker deployment package"
  type        = string
  default     = "lambda/iam-departures-worker.zip"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project   = "iam-departures-remediation"
    ManagedBy = "terraform"
  }
}

variable "alert_email" {
  description = "Optional email subscribed to failure alerts. Empty = topic only, no subscription."
  type        = string
  default     = ""
}

variable "dlq_retention_seconds" {
  description = "SQS DLQ message retention. Default 14 days (max)."
  type        = number
  default     = 1209600
}

# ── Data Sources ───────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ── S3 Bucket ──────────────────────────────────────────────────

resource "aws_s3_bucket" "remediation" {
  bucket = var.remediation_bucket
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "remediation" {
  bucket = aws_s3_bucket.remediation.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {
  bucket = aws_s3_bucket.remediation.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "remediation" {
  bucket                  = aws_s3_bucket.remediation.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_notification" "eventbridge" {
  bucket      = aws_s3_bucket.remediation.id
  eventbridge = true
}

resource "aws_s3_bucket_lifecycle_configuration" "remediation" {
  bucket = aws_s3_bucket.remediation.id
  rule {
    id     = "ArchiveAuditLogs"
    status = "Enabled"
    filter {
      prefix = "departures/audit/"
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_policy" "remediation" {
  bucket = aws_s3_bucket.remediation.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.remediation.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.remediation.arn,
          "${aws_s3_bucket.remediation.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ── DynamoDB Audit Table ───────────────────────────────────────

resource "aws_dynamodb_table" "audit" {
  name         = var.audit_dynamodb_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "iam_username"
  range_key    = "remediated_at"

  attribute {
    name = "iam_username"
    type = "S"
  }
  attribute {
    name = "remediated_at"
    type = "S"
  }
  attribute {
    name = "target_account_id"
    type = "S"
  }

  global_secondary_index {
    name            = "by-account"
    hash_key        = "target_account_id"
    range_key       = "remediated_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = var.tags
}

# ── IAM Roles ──────────────────────────────────────────────────

# Parser Lambda role (read-only)
resource "aws_iam_role" "parser" {
  name = "iam-departures-parser-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "parser" {
  name = "ParserPolicy"
  role = aws_iam_role.parser.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadManifestFromS3"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.remediation.arn}/departures/*"
      },
      {
        Sid      = "AssumeRoleInTargetAccounts"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/${var.cross_account_role_name}"
        Condition = {
          StringEquals = { "aws:PrincipalOrgID" = var.org_id }
        }
      },
      {
        # WILDCARD_OK: iam:GetUser does not support resource-level scoping.
        Sid      = "ValidateIAMUserExists"
        Effect   = "Allow"
        Action   = ["iam:GetUser"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:PrincipalOrgID" = var.org_id }
        }
      },
      {
        Sid      = "KMSDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
      },
      {
        # WILDCARD_OK: explicit deny on direct Step Functions execution is intentionally global.
        Sid      = "DenyDirectStepFunctionExecution"
        Effect   = "Deny"
        Action   = "states:StartExecution"
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/iam-departures-parser*"
      }
    ]
  })
}

# Worker Lambda role (write, cross-account)
resource "aws_iam_role" "worker" {
  name = "iam-departures-worker-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "worker" {
  name = "WorkerPolicy"
  role = aws_iam_role.worker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssumeRoleInTargetAccounts"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/${var.cross_account_role_name}"
        Condition = {
          StringEquals = { "aws:PrincipalOrgID" = var.org_id }
        }
      },
      {
        # WILDCARD_OK: the user-remediation IAM APIs in this block do not support tighter resource scoping.
        Sid    = "IAMRemediationActions"
        Effect = "Allow"
        Action = [
          "iam:GetUser", "iam:DeleteUser",
          "iam:ListAccessKeys", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
          "iam:DeleteLoginProfile",
          "iam:ListGroupsForUser", "iam:RemoveUserFromGroup",
          "iam:ListAttachedUserPolicies", "iam:DetachUserPolicy",
          "iam:ListUserPolicies", "iam:DeleteUserPolicy",
          "iam:ListMFADevices", "iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice",
          "iam:ListSigningCertificates", "iam:DeleteSigningCertificate",
          "iam:ListSSHPublicKeys", "iam:DeleteSSHPublicKey",
          "iam:ListServiceSpecificCredentials", "iam:DeleteServiceSpecificCredential",
          "iam:TagUser"
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:PrincipalOrgID" = var.org_id }
        }
      },
      {
        Sid    = "DenyProtectedUsers"
        Effect = "Deny"
        Action = "iam:*"
        Resource = [
          "arn:aws:iam::*:user/root",
          "arn:aws:iam::*:user/break-glass-*",
          "arn:aws:iam::*:user/emergency-*",
          "arn:aws:iam::*:role/*"
        ]
      },
      {
        # WILDCARD_OK: explicit deny on direct Step Functions execution is intentionally global.
        Sid      = "DenyDirectStepFunctionExecution"
        Effect   = "Deny"
        Action   = "states:StartExecution"
        Resource = "*"
      },
      {
        Sid      = "WriteAuditToDynamoDB"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.audit.arn
      },
      {
        Sid      = "WriteAuditToS3"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.remediation.arn}/departures/audit/*"
      },
      {
        Sid      = "KMSForEncryption"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${local.region}.amazonaws.com" }
        }
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/iam-departures-worker*"
      }
    ]
  })
}

# Step Function role
resource "aws_iam_role" "sfn" {
  name = "iam-departures-sfn-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
      }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "sfn" {
  name = "StepFunctionPolicy"
  role = aws_iam_role.sfn.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeLambdas"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = [aws_lambda_function.parser.arn, aws_lambda_function.worker.arn]
      },
      {
        # WILDCARD_OK: CloudWatch Logs delivery actions in Step Functions require Resource = "*".
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
          "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery", "logs:ListLogDeliveries",
          "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        # WILDCARD_OK: X-Ray telemetry APIs require Resource = "*".
        Sid    = "XRayTracing"
        Effect = "Allow"
        Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
        Resource = "*"
      }
    ]
  })
}

# EventBridge role
resource "aws_iam_role" "eventbridge" {
  name = "iam-departures-events-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "eventbridge" {
  name = "EventBridgePolicy"
  role = aws_iam_role.eventbridge.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "StartStepFunction"
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.pipeline.arn
    }]
  })
}

# ── Failure Path: DLQ + SNS + EventBridge alert rule ──────────
# Closed-loop guarantee: nothing fails silently. Async Lambda
# failures land in the DLQ for replay; Step Function failures
# raise an SNS alert so on-call sees them in real time.

resource "aws_sqs_queue" "pipeline_failures" {
  name                              = "iam-departures-dlq"
  message_retention_seconds         = var.dlq_retention_seconds
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
  tags                              = var.tags
}

resource "aws_sns_topic" "pipeline_alerts" {
  name              = "iam-departures-alerts"
  display_name      = "IAM Departures Remediation Alerts"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sns_topic_subscription" "pipeline_alerts_email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.pipeline_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "pipeline_alerts" {
  arn = aws_sns_topic.pipeline_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.pipeline_alerts.arn
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "parser_dlq_write" {
  name = "ParserDlqWrite"
  role = aws_iam_role.parser.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = aws_sqs_queue.pipeline_failures.arn
    }]
  })
}

resource "aws_iam_role_policy" "worker_dlq_write" {
  name = "WorkerDlqWrite"
  role = aws_iam_role.worker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = aws_sqs_queue.pipeline_failures.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "sfn_failure" {
  name        = "iam-departures-sfn-failure"
  description = "Page on-call when the IAM departures Step Function fails or times out"
  event_pattern = jsonencode({
    source      = ["aws.states"]
    detail-type = ["Step Functions Execution Status Change"]
    detail = {
      status          = ["FAILED", "TIMED_OUT", "ABORTED"]
      stateMachineArn = [aws_sfn_state_machine.pipeline.arn]
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "sfn_failure_to_sns" {
  rule = aws_cloudwatch_event_rule.sfn_failure.name
  arn  = aws_sns_topic.pipeline_alerts.arn
}

# ── Lambda Functions ───────────────────────────────────────────

resource "aws_lambda_function" "parser" {
  function_name = "iam-departures-parser"
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  s3_bucket     = aws_s3_bucket.remediation.id
  s3_key        = var.parser_code_s3_key
  role          = aws_iam_role.parser.arn
  timeout       = 300
  memory_size   = 256

  dead_letter_config {
    target_arn = aws_sqs_queue.pipeline_failures.arn
  }

  environment {
    variables = {
      IAM_REMEDIATION_BUCKET = var.remediation_bucket
      IAM_GRACE_PERIOD_DAYS  = tostring(var.grace_period_days)
      IAM_CROSS_ACCOUNT_ROLE = var.cross_account_role_name
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = var.tags
}

resource "aws_lambda_function" "worker" {
  function_name = "iam-departures-worker"
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  s3_bucket     = aws_s3_bucket.remediation.id
  s3_key        = var.worker_code_s3_key
  role          = aws_iam_role.worker.arn
  timeout       = 900
  memory_size   = 256

  dead_letter_config {
    target_arn = aws_sqs_queue.pipeline_failures.arn
  }

  environment {
    variables = {
      IAM_REMEDIATION_BUCKET     = var.remediation_bucket
      IAM_AUDIT_DYNAMODB_TABLE   = var.audit_dynamodb_table
      IAM_CROSS_ACCOUNT_ROLE     = var.cross_account_role_name
      KMS_KEY_ARN                = var.kms_key_arn
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = var.tags
}

# ── Step Function ──────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/states/iam-departures-pipeline"
  retention_in_days = 365
  tags              = var.tags
}

resource "aws_sfn_state_machine" "pipeline" {
  name     = "iam-departures-pipeline"
  role_arn = aws_iam_role.sfn.arn

  definition = jsonencode({
    Comment = "IAM Departures Remediation Pipeline"
    StartAt = "ParseManifest"
    States = {
      ParseManifest = {
        Type       = "Task"
        Resource   = aws_lambda_function.parser.arn
        ResultPath = "$.parsed"
        Next       = "CheckValidatedEntries"
        Retry      = [{ ErrorEquals = ["States.TaskFailed"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], Next = "ParseFailed", ResultPath = "$.error" }]
      }
      CheckValidatedEntries = {
        Type    = "Choice"
        Choices = [{ Variable = "$.parsed.validated_count", NumericGreaterThan = 0, Next = "RemediateUsers" }]
        Default = "NoUsersToRemediate"
      }
      RemediateUsers = {
        Type           = "Map"
        ItemsPath      = "$.parsed.validated_entries"
        MaxConcurrency = 10
        Iterator = {
          StartAt = "RemediateSingleUser"
          States = {
            RemediateSingleUser = {
              Type     = "Task"
              Resource = aws_lambda_function.worker.arn
              End      = true
              Retry    = [{ ErrorEquals = ["States.TaskFailed"], MaxAttempts = 1, IntervalSeconds = 10 }]
              Catch    = [{ ErrorEquals = ["States.ALL"], Next = "UserRemediationFailed", ResultPath = "$.error" }]
            }
            UserRemediationFailed = {
              Type       = "Pass"
              Result     = "FAILED"
              ResultPath = "$.remediation_status"
              End        = true
            }
          }
        }
        Next = "GenerateSummary"
      }
      GenerateSummary = {
        Type = "Pass"
        Parameters = {
          status        = "COMPLETED"
          "timestamp.$" = "$$.State.EnteredTime"
        }
        End = true
      }
      NoUsersToRemediate = {
        Type   = "Pass"
        Result = { status = "NO_ACTION", reason = "No validated entries to remediate" }
        End    = true
      }
      ParseFailed = {
        Type  = "Fail"
        Cause = "Manifest parsing failed"
        Error = "ParseError"
      }
    }
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  tags = var.tags
}

# ── EventBridge Rule ───────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "s3_trigger" {
  name        = "iam-departures-s3-trigger"
  description = "Trigger Step Function when new manifest is uploaded to S3"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = { name = [var.remediation_bucket] }
      object = { key = [{ prefix = "departures/" }, { suffix = ".json" }] }
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "sfn" {
  rule     = aws_cloudwatch_event_rule.s3_trigger.name
  arn      = aws_sfn_state_machine.pipeline.arn
  role_arn = aws_iam_role.eventbridge.arn
}

# ── Outputs ────────────────────────────────────────────────────

output "parser_role_arn" {
  description = "Lambda Parser execution role ARN"
  value       = aws_iam_role.parser.arn
}

output "worker_role_arn" {
  description = "Lambda Worker execution role ARN"
  value       = aws_iam_role.worker.arn
}

output "sfn_role_arn" {
  description = "Step Function execution role ARN"
  value       = aws_iam_role.sfn.arn
}

output "sfn_arn" {
  description = "Step Function state machine ARN"
  value       = aws_sfn_state_machine.pipeline.arn
}

output "s3_bucket_arn" {
  description = "Remediation S3 bucket ARN"
  value       = aws_s3_bucket.remediation.arn
}

output "audit_table_arn" {
  description = "DynamoDB audit table ARN"
  value       = aws_dynamodb_table.audit.arn
}

output "pipeline_failure_dlq_arn" {
  description = "SQS DLQ for failed Lambda async invocations (replay source)"
  value       = aws_sqs_queue.pipeline_failures.arn
}

output "pipeline_alerts_topic_arn" {
  description = "SNS topic that fires on Step Function failure / timeout / abort"
  value       = aws_sns_topic.pipeline_alerts.arn
}
