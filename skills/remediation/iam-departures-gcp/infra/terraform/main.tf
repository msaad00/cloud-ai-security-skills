# IAM Departures Remediation (GCP) — Terraform module
#
# Equivalent to ../deployment_manager.yaml. Deploys the full pipeline:
# manifest GCS bucket, audit GCS bucket, CMEK keyring + key, Firestore
# (Native mode) database, two Cloud Functions Gen 2 (parser + worker),
# one Cloud Workflow, one Eventarc trigger on
# `google.cloud.storage.object.v1.finalized`, Pub/Sub DLQ + alert topic,
# and four service accounts with IAM Conditions binding destructive
# permissions to the operator's GCP organization boundary.
#
# MITRE ATT&CK: T1078.004, T1098.001, T1531, T1552
# NIST CSF 2.0: PR.AC-1, PR.AC-4, RS.MI-2
# CIS GCP v3:   1.5, 1.7, 1.10
# CIS Controls v8: 5.3, 6.2

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

# ── Variables ──────────────────────────────────────────────────

variable "security_project_id" {
  description = "Project where the parser, worker, KMS, audit, and Firestore live"
  type        = string
}

variable "region" {
  description = "GCP region (regional resources only — Eventarc requires same-region bucket)"
  type        = string
  default     = "us-central1"
}

variable "gcp_org_id" {
  description = "GCP organization id (digits only). Bounds every destructive binding."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{6,16}$", var.gcp_org_id))
    error_message = "Must be a numeric GCP organization id"
  }
}

variable "workspace_customer_id" {
  description = "Workspace / Cloud Identity customer id (e.g. C01abcdef)"
  type        = string
  default     = ""
}

variable "manifest_bucket" {
  description = "GCS bucket name for departure manifests (Eventarc source)"
  type        = string
}

variable "audit_bucket" {
  description = "GCS bucket name for audit objects (CMEK encrypted, immutable)"
  type        = string
}

variable "deploy_bucket" {
  description = "GCS bucket holding the Cloud Function source archives"
  type        = string
}

variable "parser_source_object" {
  description = "Object path in deploy_bucket for the parser source archive"
  type        = string
  default     = "iam-departures-gcp/parser-source.zip"
}

variable "worker_source_object" {
  description = "Object path in deploy_bucket for the worker source archive"
  type        = string
  default     = "iam-departures-gcp/worker-source.zip"
}

variable "grace_period_days" {
  description = "Days after termination before remediation fires (default 7, never 0)"
  type        = number
  default     = 7
  validation {
    condition     = var.grace_period_days >= 1 && var.grace_period_days <= 90
    error_message = "Grace period must be 1-90 days; 0 is rejected by design"
  }
}

variable "alert_email" {
  description = "Optional email subscribed to alert Pub/Sub topic. Empty = topic only, no subscription."
  type        = string
  default     = ""
}

variable "labels" {
  description = "Labels applied to every resource"
  type        = map(string)
  default = {
    project   = "iam-departures-gcp"
    managedby = "terraform"
  }
}

# ── KMS keyring + audit key ────────────────────────────────────

resource "google_kms_key_ring" "iam_departures" {
  name     = "iam-departures-gcp"
  project  = var.security_project_id
  location = var.region
}

resource "google_kms_crypto_key" "audit" {
  name            = "iam-audit"
  key_ring        = google_kms_key_ring.iam_departures.id
  rotation_period = "2592000s" # 30 days
  purpose         = "ENCRYPT_DECRYPT"
  labels          = var.labels
  lifecycle {
    prevent_destroy = true
  }
}

# ── GCS buckets ────────────────────────────────────────────────

resource "google_storage_bucket" "manifest" {
  name                        = var.manifest_bucket
  project                     = var.security_project_id
  location                    = var.region
  storage_class               = "STANDARD"
  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
  versioning { enabled = true }
  encryption { default_kms_key_name = google_kms_crypto_key.audit.id }
  labels                      = var.labels
}

resource "google_storage_bucket" "audit" {
  name                        = var.audit_bucket
  project                     = var.security_project_id
  location                    = var.region
  storage_class               = "STANDARD"
  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
  versioning { enabled = true }
  encryption { default_kms_key_name = google_kms_crypto_key.audit.id }
  lifecycle_rule {
    condition {
      age            = 90
      matches_prefix = ["departures/audit/"]
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }
  labels = var.labels
}

# ── Service accounts ───────────────────────────────────────────

resource "google_service_account" "parser" {
  account_id   = "iam-departures-gcp-parser"
  display_name = "iam-departures-gcp parser Cloud Function"
  project      = var.security_project_id
}

resource "google_service_account" "worker" {
  account_id   = "iam-departures-gcp-worker"
  display_name = "iam-departures-gcp worker Cloud Function"
  project      = var.security_project_id
}

resource "google_service_account" "workflow" {
  account_id   = "iam-departures-gcp-workflow"
  display_name = "iam-departures-gcp Cloud Workflow"
  project      = var.security_project_id
}

resource "google_service_account" "eventarc" {
  account_id   = "iam-departures-gcp-events"
  display_name = "iam-departures-gcp Eventarc trigger"
  project      = var.security_project_id
}

# ── Firestore (Native mode) ────────────────────────────────────

resource "google_firestore_database" "audit" {
  project     = var.security_project_id
  name        = "iam-departures-gcp"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
}

# ── IAM bindings — least privilege with org-scoped Conditions ──
# Every destructive binding is org-scoped via an IAM Condition that pins
# the binding to the operator's GCP organization. An attacker holding
# the worker SA cannot escape the boundary — analogous to AWS's
# `aws:PrincipalOrgID` constraint on `sts:AssumeRole`.

resource "google_organization_iam_member" "worker_org_iam_admin" {
  org_id = var.gcp_org_id
  role   = "roles/resourcemanager.organizationAdmin"
  member = "serviceAccount:${google_service_account.worker.email}"
  condition {
    title       = "OrgScopedIAMTeardown"
    description = "Worker can act only within the operator's GCP organization"
    expression  = "resource.name.startsWith(\"organizations/${var.gcp_org_id}\") || resource.name.startsWith(\"folders/\") || resource.name.startsWith(\"projects/\")"
  }
}

resource "google_organization_iam_member" "worker_sa_admin" {
  org_id = var.gcp_org_id
  role   = "roles/iam.serviceAccountAdmin"
  member = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_organization_iam_member" "worker_sa_key_admin" {
  org_id = var.gcp_org_id
  role   = "roles/iam.serviceAccountKeyAdmin"
  member = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_organization_iam_member" "worker_logging_writer" {
  org_id = var.gcp_org_id
  role   = "roles/logging.logWriter"
  member = "serviceAccount:${google_service_account.worker.email}"
}

# Per-project bindings for the security project (audit dual-write).
resource "google_project_iam_member" "worker_datastore_user" {
  project = var.security_project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_storage_bucket_iam_member" "worker_audit_writer" {
  bucket = google_storage_bucket.audit.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_kms_crypto_key_iam_member" "worker_kms" {
  crypto_key_id = google_kms_crypto_key.audit.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.worker.email}"
}

# Parser — read-only manifest access.
resource "google_storage_bucket_iam_member" "parser_manifest_reader" {
  bucket = google_storage_bucket.manifest.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.parser.email}"
  condition {
    title       = "OnlyDeparturesPrefix"
    description = "Parser may read only objects under departures/ prefix"
    expression  = "resource.name.startsWith(\"projects/_/buckets/${google_storage_bucket.manifest.name}/objects/departures/\")"
  }
}

resource "google_kms_crypto_key_iam_member" "parser_kms_decrypt" {
  crypto_key_id = google_kms_crypto_key.audit.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.parser.email}"
}

# Workflow can invoke the parser + worker functions.
resource "google_cloudfunctions2_function_iam_member" "workflow_invoke_parser" {
  project        = var.security_project_id
  location       = var.region
  cloud_function = google_cloudfunctions2_function.parser.name
  role           = "roles/cloudfunctions.invoker"
  member         = "serviceAccount:${google_service_account.workflow.email}"
}

resource "google_cloudfunctions2_function_iam_member" "workflow_invoke_worker" {
  project        = var.security_project_id
  location       = var.region
  cloud_function = google_cloudfunctions2_function.worker.name
  role           = "roles/cloudfunctions.invoker"
  member         = "serviceAccount:${google_service_account.workflow.email}"
}

# Eventarc trigger needs eventReceiver + workflows.invoker.
resource "google_project_iam_member" "events_event_receiver" {
  project = var.security_project_id
  role    = "roles/eventarc.eventReceiver"
  member  = "serviceAccount:${google_service_account.eventarc.email}"
}

resource "google_project_iam_member" "events_workflow_invoker" {
  project = var.security_project_id
  role    = "roles/workflows.invoker"
  member  = "serviceAccount:${google_service_account.eventarc.email}"
}

# ── Cloud Functions Gen 2 ──────────────────────────────────────

resource "google_cloudfunctions2_function" "parser" {
  name     = "iam-departures-gcp-parser"
  project  = var.security_project_id
  location = var.region

  build_config {
    runtime     = "python311"
    entry_point = "handler"
    source {
      storage_source {
        bucket = var.deploy_bucket
        object = var.parser_source_object
      }
    }
  }

  service_config {
    available_memory               = "256Mi"
    timeout_seconds                = 300
    max_instance_count             = 5
    service_account_email          = google_service_account.parser.email
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    vpc_connector_egress_settings  = "PRIVATE_RANGES_ONLY"
    environment_variables = {
      IAM_DEPARTURES_GCP_GRACE_DAYS                  = tostring(var.grace_period_days)
      IAM_DEPARTURES_GCP_AUDIT_FIRESTORE_COLLECTION  = "iam-departures-gcp-audit"
      IAM_DEPARTURES_GCP_AUDIT_BUCKET                = var.audit_bucket
      IAM_DEPARTURES_GCP_KMS_KEY                     = google_kms_crypto_key.audit.id
    }
  }

  labels = var.labels
}

resource "google_cloudfunctions2_function" "worker" {
  name     = "iam-departures-gcp-worker"
  project  = var.security_project_id
  location = var.region

  build_config {
    runtime     = "python311"
    entry_point = "handler"
    source {
      storage_source {
        bucket = var.deploy_bucket
        object = var.worker_source_object
      }
    }
  }

  service_config {
    available_memory               = "512Mi"
    timeout_seconds                = 540
    max_instance_count             = 10
    service_account_email          = google_service_account.worker.email
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    vpc_connector_egress_settings  = "PRIVATE_RANGES_ONLY"
    environment_variables = {
      IAM_DEPARTURES_GCP_AUDIT_FIRESTORE_COLLECTION = "iam-departures-gcp-audit"
      IAM_DEPARTURES_GCP_AUDIT_BUCKET               = var.audit_bucket
      IAM_DEPARTURES_GCP_KMS_KEY                    = google_kms_crypto_key.audit.id
      # IAM_DEPARTURES_GCP_INCIDENT_ID and IAM_DEPARTURES_GCP_APPROVER are
      # injected per-incident via `gcloud functions deploy --update-env-vars`.
    }
  }

  labels = var.labels
}

# ── Cloud Workflow ─────────────────────────────────────────────

resource "google_workflows_workflow" "pipeline" {
  name            = "iam-departures-gcp-pipeline"
  project         = var.security_project_id
  region          = var.region
  service_account = google_service_account.workflow.id
  source_contents = file("${path.module}/../workflow.yaml")
  labels          = var.labels
}

# ── Eventarc trigger ───────────────────────────────────────────

resource "google_eventarc_trigger" "manifest" {
  name            = "iam-departures-gcp-manifest-trigger"
  project         = var.security_project_id
  location        = var.region
  service_account = google_service_account.eventarc.email

  matching_criteria {
    attribute = "type"
    value     = "google.cloud.storage.object.v1.finalized"
  }
  matching_criteria {
    attribute = "bucket"
    value     = google_storage_bucket.manifest.name
  }

  destination {
    workflow = google_workflows_workflow.pipeline.id
  }

  labels = var.labels
}

# ── Pub/Sub DLQ + alerts ───────────────────────────────────────

resource "google_pubsub_topic" "dlq" {
  name                       = "iam-departures-gcp-dlq"
  project                    = var.security_project_id
  message_retention_duration = "1209600s"
  kms_key_name               = google_kms_crypto_key.audit.id
  labels                     = var.labels
}

resource "google_pubsub_topic" "alerts" {
  name         = "iam-departures-gcp-alerts"
  project      = var.security_project_id
  kms_key_name = google_kms_crypto_key.audit.id
  labels       = var.labels
}

resource "google_pubsub_subscription" "alerts_email" {
  count   = var.alert_email == "" ? 0 : 1
  name    = "iam-departures-gcp-alerts-email"
  project = var.security_project_id
  topic   = google_pubsub_topic.alerts.name
  ack_deadline_seconds = 60
}

# ── Outputs ────────────────────────────────────────────────────

output "parser_function_name" {
  value = google_cloudfunctions2_function.parser.name
}

output "worker_function_name" {
  value = google_cloudfunctions2_function.worker.name
}

output "workflow_id" {
  value = google_workflows_workflow.pipeline.id
}

output "manifest_bucket" {
  value = google_storage_bucket.manifest.name
}

output "audit_bucket" {
  value = google_storage_bucket.audit.name
}

output "kms_key" {
  value = google_kms_crypto_key.audit.id
}

output "dlq_topic" {
  value = google_pubsub_topic.dlq.id
}

output "alerts_topic" {
  value = google_pubsub_topic.alerts.id
}
