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

resource "google_pubsub_topic" "detect" {
  name = "cloud-security-detect"
}

resource "google_pubsub_topic" "findings" {
  name = "cloud-security-findings"
}

resource "google_firestore_database" "dedupe" {
  project     = var.project_id
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
}

resource "google_service_account" "ingest" {
  account_id   = "cloud-security-ingest"
  display_name = "cloud-ai-security ingest runner"
}

resource "google_service_account" "detect" {
  account_id   = "cloud-security-detect"
  display_name = "cloud-ai-security detect runner"
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
  name     = "cloud-security-ingest"
  location = var.region

  build_config {
    runtime     = "python311"
    entry_point = "handle_gcs_event"
    source {
      storage_source {
        bucket = var.function_source_bucket
        object = var.ingest_source_object
      }
    }
  }

  service_config {
    available_memory      = "512M"
    timeout_seconds       = 300
    service_account_email = google_service_account.ingest.email
    environment_variables = {
      INGEST_SKILL_CMD = var.ingest_skill_command
      DETECT_TOPIC     = "projects/${var.project_id}/topics/${google_pubsub_topic.detect.name}"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.storage.object.v1.finalized"
    event_filters {
      attribute = "bucket"
      value     = var.source_bucket_name
    }
    retry_policy = "RETRY_POLICY_RETRY"
  }
}

resource "google_cloudfunctions2_function" "detect" {
  name     = "cloud-security-detect"
  location = var.region

  build_config {
    runtime     = "python311"
    entry_point = "handle_pubsub_event"
    source {
      storage_source {
        bucket = var.function_source_bucket
        object = var.detect_source_object
      }
    }
  }

  service_config {
    available_memory      = "512M"
    timeout_seconds       = 300
    service_account_email = google_service_account.detect.email
    environment_variables = {
      DETECT_SKILL_CMD = var.detect_skill_command
      DEDUPE_COLLECTION = var.dedupe_collection
      FINDINGS_TOPIC   = "projects/${var.project_id}/topics/${google_pubsub_topic.findings.name}"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.detect.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }

  depends_on = [google_firestore_database.dedupe]
}

output "detect_topic" {
  value = google_pubsub_topic.detect.id
}

output "findings_topic" {
  value = google_pubsub_topic.findings.id
}
