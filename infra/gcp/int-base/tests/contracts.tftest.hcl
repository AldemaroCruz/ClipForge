# Authored digest/version fixtures only. Native mock plans never contact GCP or AR.
variables {
  runtime_image   = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  secret_versions = { app_password = "1", migrator_password = "1", postgres_ca = "1", bootstrap_admin = "1" }
}
mock_provider "google" {
  mock_data "google_service_account" {
    defaults = {
      email = "clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com"
      name  = "projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com"
    }
  }
}
override_data {
  target = data.google_project.existing
  values = { number = "816643438938" }
}
run "economical_defaults" {
  command = plan
  assert {
    condition     = google_compute_instance.postgres.machine_type == "e2-micro" && google_compute_disk.postgres.size == 20
    error_message = "Default cost profile changed."
  }
  assert {
    condition     = google_compute_instance.postgres.deletion_protection && !google_compute_instance.postgres.boot_disk[0].auto_delete
    error_message = "VM and disks must be retained."
  }
  assert {
    condition     = length(google_compute_instance.postgres.network_interface[0].access_config) == 0
    error_message = "PostgreSQL must have no public address."
  }
}
run "evaluate_small" {
  command = plan
  variables { machine_type = "e2-small" }
  assert {
    condition     = google_compute_instance.postgres.machine_type == "e2-small"
    error_message = "The small comparison profile must be available without applying."
  }
}
run "reject_public_network" {
  command = plan
  variables { run_subnet_cidr = "0.0.0.0/0" }
  expect_failures = [var.run_subnet_cidr]
}
run "reject_wrong_project" {
  command = plan
  variables { project_id = "other-project" }
  expect_failures = [var.project_id]
}
run "reject_small_data_disk" {
  command = plan
  variables { data_disk_gb = 1 }
  expect_failures = [var.data_disk_gb]
}
run "reject_overlap" {
  command = plan
  variables { postgres_subnet_cidr = "10.80.0.0/28" }
  expect_failures = [terraform_data.boundary]
}

run "foundation_has_no_runtime" {
  command = plan
  variables { secret_versions = null }
  assert {
    condition     = length(google_cloud_run_v2_service.api) == 0 && length(google_cloud_run_v2_job.task) == 0
    error_message = "Foundation must not create a service referencing absent secret versions."
  }
  assert {
    condition     = google_logging_project_bucket_config.access.retention_days == 30 && length(google_project_iam_audit_config.storage_access.audit_log_config) == 3
    error_message = "Audit access control must be explicit."
  }
}
run "runtime_iap_jobs" {
  command = plan
  variables { stage = "runtime" }
  assert {
    condition     = google_cloud_run_v2_service.api[0].iap_enabled && google_cloud_run_v2_service.api[0].template[0].scaling[0].max_instance_count == 1
    error_message = "Runtime must retain IAP and API capacity cap."
  }
  assert {
    condition     = length(google_cloud_run_v2_job.task) == 3 && alltrue([for job in google_cloud_run_v2_job.task : job.template[0].parallelism == 1 && job.template[0].task_count == 1])
    error_message = "Worker/migrate/bootstrap must each be one task."
  }
  assert {
    condition     = google_iap_web_cloud_run_service_iam_member.pilot_admin[0].member == "user:admin@ixbalam.studio"
    error_message = "No additional IAP user is approved."
  }
}
run "reject_latest_image" {
  command = plan
  variables { runtime_image = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime:latest" }
  expect_failures = [var.runtime_image]
}
run "reject_latest_secret" {
  command = plan
  variables { secret_versions = { app_password = "latest", migrator_password = "1", postgres_ca = "1", bootstrap_admin = "1" } }
  expect_failures = [var.secret_versions]
}
