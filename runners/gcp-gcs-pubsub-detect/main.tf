terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "source_bucket_name" {
  type = string
}

variable "function_source_bucket" {
  type = string
}

variable "ingest_source_object" {
  type = string
}

variable "detect_source_object" {
  type = string
}

variable "ingest_skill_command" {
  type = string
}

variable "detect_skill_command" {
  type = string
}

variable "dedupe_collection" {
  type    = string
  default = "runner_dedupe"
}

variable "dedupe_ttl_days" {
  type    = number
  default = 30
}

variable "max_instance_count" {
  type    = number
  default = 50
}

variable "name_prefix" {
  type    = string
  default = "cloud-security"
}

variable "service_account_prefix" {
  type        = string
  default     = "cloud-security"
  description = "Service account IDs are <prefix>-ingest / <prefix>-detect / <prefix>-build and must stay within 30 characters."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,22}$", var.service_account_prefix))
    error_message = "service_account_prefix must be 5-23 lowercase letters, digits, or hyphens."
  }
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "firestore_database" {
  type    = string
  default = "(default)"
}

variable "firestore_deletion_policy" {
  type    = string
  default = "ABANDON"

  validation {
    condition     = contains(["ABANDON", "DELETE"], var.firestore_deletion_policy)
    error_message = "firestore_deletion_policy must be ABANDON or DELETE."
  }
}

resource "google_pubsub_topic" "detect" {
  name   = "${var.name_prefix}-detect"
  labels = var.labels
}

resource "google_pubsub_topic" "findings" {
  name   = "${var.name_prefix}-findings"
  labels = var.labels
}

resource "google_firestore_database" "dedupe" {
  project         = var.project_id
  name            = var.firestore_database
  location_id     = var.region
  type            = "FIRESTORE_NATIVE"
  deletion_policy = var.firestore_deletion_policy
}

resource "google_firestore_field" "dedupe_expires_at" {
  project    = var.project_id
  database   = google_firestore_database.dedupe.name
  collection = var.dedupe_collection
  field      = "expires_at"

  ttl_config {}

  depends_on = [google_firestore_database.dedupe]
}

resource "google_service_account" "ingest" {
  account_id   = "${var.service_account_prefix}-ingest"
  display_name = "cloud-ai-security ingest runner"
}

resource "google_service_account" "detect" {
  account_id   = "${var.service_account_prefix}-detect"
  display_name = "cloud-ai-security detect runner"
}

resource "google_service_account" "build" {
  account_id   = "${var.service_account_prefix}-build"
  display_name = "cloud-ai-security runner function build"
}

# Cloud Functions builds run as this account instead of the project's default
# compute account, which may have no roles at all.
resource "google_project_iam_member" "build_builder" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = "serviceAccount:${google_service_account.build.email}"
}

resource "google_storage_bucket_iam_member" "build_source_reader" {
  bucket = var.function_source_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.build.email}"
}

data "google_storage_project_service_account" "gcs_agent" {
  project = var.project_id
}

# Eventarc Cloud Storage triggers deliver through Pub/Sub, published by the
# Cloud Storage service agent.
resource "google_project_iam_member" "gcs_agent_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${data.google_storage_project_service_account.gcs_agent.email_address}"
}

# Each function's own service account is also its Eventarc trigger identity.
resource "google_project_iam_member" "ingest_event_receiver" {
  project = var.project_id
  role    = "roles/eventarc.eventReceiver"
  member  = "serviceAccount:${google_service_account.ingest.email}"
}

resource "google_project_iam_member" "detect_event_receiver" {
  project = var.project_id
  role    = "roles/eventarc.eventReceiver"
  member  = "serviceAccount:${google_service_account.detect.email}"
}

resource "google_cloud_run_service_iam_member" "ingest_trigger_invoker" {
  location = var.region
  service  = google_cloudfunctions2_function.ingest.service_config[0].service
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.ingest.email}"
}

resource "google_cloud_run_service_iam_member" "detect_trigger_invoker" {
  location = var.region
  service  = google_cloudfunctions2_function.detect.service_config[0].service
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.detect.email}"
}

resource "google_project_iam_member" "ingest_storage_reader" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.ingest.email}"
}

resource "google_pubsub_topic_iam_member" "ingest_publisher" {
  topic  = google_pubsub_topic.detect.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.ingest.email}"
}

resource "google_project_iam_member" "detect_firestore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.detect.email}"
}

resource "google_pubsub_topic_iam_member" "detect_publisher" {
  topic  = google_pubsub_topic.findings.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.detect.email}"
}

resource "google_storage_bucket_iam_member" "source_eventarc_reader" {
  bucket = var.source_bucket_name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.ingest.email}"
}

resource "google_cloudfunctions2_function" "ingest" {
  name     = "${var.name_prefix}-ingest"
  location = var.region
  labels   = var.labels

  build_config {
    runtime         = "python311"
    service_account = google_service_account.build.id
    entry_point     = "handle_gcs_event"
    environment_variables = {
      GOOGLE_FUNCTION_SOURCE = "ingest_handler.py"
    }
    source {
      storage_source {
        bucket = var.function_source_bucket
        object = var.ingest_source_object
      }
    }
  }

  service_config {
    available_memory      = "512M"
    max_instance_count    = var.max_instance_count
    timeout_seconds       = 300
    service_account_email = google_service_account.ingest.email
    environment_variables = {
      INGEST_SKILL_CMD = var.ingest_skill_command
      DETECT_TOPIC     = "projects/${var.project_id}/topics/${google_pubsub_topic.detect.name}"
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.storage.object.v1.finalized"
    service_account_email = google_service_account.ingest.email
    event_filters {
      attribute = "bucket"
      value     = var.source_bucket_name
    }
    retry_policy = "RETRY_POLICY_RETRY"
  }

  depends_on = [
    google_project_iam_member.build_builder,
    google_storage_bucket_iam_member.build_source_reader,
    google_project_iam_member.gcs_agent_pubsub_publisher,
    google_project_iam_member.ingest_event_receiver,
  ]
}

resource "google_cloudfunctions2_function" "detect" {
  name     = "${var.name_prefix}-detect"
  location = var.region
  labels   = var.labels

  build_config {
    runtime         = "python311"
    service_account = google_service_account.build.id
    entry_point     = "handle_pubsub_event"
    environment_variables = {
      GOOGLE_FUNCTION_SOURCE = "detect_handler.py"
    }
    source {
      storage_source {
        bucket = var.function_source_bucket
        object = var.detect_source_object
      }
    }
  }

  service_config {
    available_memory      = "512M"
    max_instance_count    = var.max_instance_count
    timeout_seconds       = 300
    service_account_email = google_service_account.detect.email
    environment_variables = {
      DETECT_SKILL_CMD  = var.detect_skill_command
      DEDUPE_COLLECTION = var.dedupe_collection
      DEDUPE_DATABASE   = google_firestore_database.dedupe.name
      DEDUPE_TTL_DAYS   = tostring(var.dedupe_ttl_days)
      FINDINGS_TOPIC    = "projects/${var.project_id}/topics/${google_pubsub_topic.findings.name}"
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    service_account_email = google_service_account.detect.email
    pubsub_topic          = google_pubsub_topic.detect.id
    retry_policy          = "RETRY_POLICY_RETRY"
  }

  depends_on = [
    google_firestore_database.dedupe,
    google_firestore_field.dedupe_expires_at,
    google_project_iam_member.build_builder,
    google_storage_bucket_iam_member.build_source_reader,
    google_project_iam_member.detect_event_receiver,
  ]
}

output "detect_topic" {
  value = google_pubsub_topic.detect.id
}

output "findings_topic" {
  value = google_pubsub_topic.findings.id
}
