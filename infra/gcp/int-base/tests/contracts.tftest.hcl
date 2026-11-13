mock_provider "google" {
  mock_data "google_service_account" {
    defaults = { email = "clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com" }
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
