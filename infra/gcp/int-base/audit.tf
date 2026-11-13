# DATA_READ/WRITE enablement is project/service scoped in GCP, not bucket scoped.
# This intentionally increases audit volume for *all* GCS buckets in this project;
# the dedicated sink/view below retain only the two pilot buckets. Existing
# _Default routing remains unchanged, and may store a second billed copy.
resource "google_project_iam_audit_config" "storage_access" {
  project = var.project_id
  service = "storage.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}
resource "google_logging_project_bucket_config" "access" {
  project        = var.project_id
  location       = local.region
  bucket_id      = "clipforge-int-access"
  retention_days = 30
  description    = "Private GCS pilot Data Access audit records; content is never application output."
}
resource "google_logging_project_sink" "access" {
  project     = var.project_id
  name        = "clipforge-int-access"
  destination = "logging.googleapis.com/${google_logging_project_bucket_config.access.id}"
  # Same-project log-bucket routing needs no writer SA or project-wide writer grant.
  unique_writer_identity = false
  filter                 = <<-FILTER
    log_id("cloudaudit.googleapis.com/data_access")
    resource.type="gcs_bucket"
    (resource.labels.bucket_name="clipforgebeta2-int-media" OR resource.labels.bucket_name="clipforgebeta2-int-backups")
  FILTER
}
resource "google_logging_log_view" "access" {
  parent   = "projects/${var.project_id}"
  location = local.region
  bucket   = google_logging_project_bucket_config.access.bucket_id
  name     = "pilot-access"
  filter   = "LOG_ID(\"cloudaudit.googleapis.com/data_access\")"
}
resource "google_logging_log_view_iam_member" "audit_reader" {
  parent   = google_logging_log_view.access.parent
  location = local.region
  bucket   = google_logging_log_view.access.bucket
  name     = google_logging_log_view.access.name
  role     = "roles/logging.viewAccessor"
  member   = "user:admin@ixbalam.studio"
}
