# Source-only native mock for the Noble runtime connection. All identities and
# version numbers below are fixtures for Terraform's mock provider.
variables {
  runtime_image        = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  db01_noble_candidate = { image_name = "ubuntu-2404-noble-amd64-v20000101", image_id = "9000000000000000001" }
}

mock_provider "google" {
  override_during = plan
  mock_data "google_compute_image" {
    defaults = {
      image_id  = "5913446147369107523"
      status    = "READY"
      self_link = "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-trixie-v20261116"
    }
  }
  mock_resource "google_service_account" {
    defaults = {
      email = "clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"
      name  = "projects/clipforgebeta2/serviceAccounts/clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"
    }
  }
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

override_data {
  target = data.google_service_account.existing["deploy"]
  values = {
    email = "clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
    name  = "projects/clipforgebeta2/serviceAccounts/clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
  }
}

override_data {
  target = data.google_compute_image.noble[0]
  values = {
    image_id     = "9000000000000000001"
    status       = "READY"
    family       = "ubuntu-2404-lts-amd64"
    self_link    = "https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20000101"
    licenses     = ["https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-2404-lts"]
    disk_size_gb = 10
  }
}

override_resource {
  target          = google_compute_disk.noble_boot[0]
  override_during = plan
  values          = { source_image_id = "9000000000000000001" }
}

run "postgres_acceptance_path_before_application" {
  command = plan
  variables { noble_postgres_from_run = true }

  assert {
    condition = (
      length(google_cloud_run_v2_service.api) == 0 && length(google_cloud_run_v2_job.task) == 0 &&
      length(google_compute_firewall.noble_postgres_from_run) == 1 &&
      google_compute_firewall.noble_postgres_from_run[0].direction == "INGRESS" &&
      toset(google_compute_firewall.noble_postgres_from_run[0].source_ranges) == toset(["10.80.0.0/26"]) &&
      toset(google_compute_firewall.noble_postgres_from_run[0].target_service_accounts) == toset([google_service_account.noble[0].email]) &&
      one(google_compute_firewall.noble_postgres_from_run[0].allow).protocol == "tcp" &&
      toset(one(google_compute_firewall.noble_postgres_from_run[0].allow).ports) == toset(["5432"])
    )
    error_message = "The acceptance rule must be limited to the INT Run subnet, the Noble identity, and TCP/5432."
  }
}

run "api_and_jobs_use_noble_verify_full" {
  command = plan
  variables {
    stage                   = "runtime"
    noble_postgres_from_run = true
    secret_versions         = { app_password = "12", migrator_password = "13", postgres_ca = "14", bootstrap_admin = "15" }
  }

  assert {
    condition = (
      length(google_compute_instance.noble) == 1 && google_compute_instance.postgres.name == "clipforge-int-base-postgres" &&
      google_compute_address.postgres.address == "10.80.1.2" && google_compute_address.noble[0].address == "10.80.1.3" &&
      google_cloud_run_v2_service.api[0].iap_enabled &&
      toset(keys(google_cloud_run_v2_job.task)) == toset(["worker", "bootstrap"]) &&
      toset(keys(google_cloud_run_v2_job_iam_member.protected_operator)) == toset(keys(google_cloud_run_v2_job.task)) &&
      alltrue([for env in concat(
        [google_cloud_run_v2_service.api[0].template[0].containers[0].env],
        [for job in google_cloud_run_v2_job.task : job.template[0].template[0].containers[0].env]
        ) : try(
        one([for item in env : item.value if item.name == "CLIPFORGE_DATABASE_HOST"]) == "10.80.1.3" &&
        one([for item in env : item.value if item.name == "CLIPFORGE_DATABASE_SSL_MODE"]) == "verify-full",
      false)])
    )
    error_message = "The API and jobs must keep private Noble with verify-full and preserve the Debian address."
  }
}

run "opening_connection_without_noble_is_rejected" {
  command = plan
  variables {
    db01_noble_candidate    = null
    noble_postgres_from_run = true
  }
  expect_failures = [var.noble_postgres_from_run]
}

run "runtime_without_noble_connection_is_rejected" {
  command = plan
  variables {
    stage           = "runtime"
    secret_versions = { app_password = "12", migrator_password = "13", postgres_ca = "14", bootstrap_admin = "15" }
  }
  expect_failures = [var.noble_postgres_from_run]
}

run "debian_runtime_retains_existing_jobs" {
  command = plan
  variables {
    stage                = "runtime"
    db01_noble_candidate = null
    secret_versions      = { app_password = "12", migrator_password = "13", postgres_ca = "14", bootstrap_admin = "15" }
  }
  assert {
    condition     = toset(keys(google_cloud_run_v2_job.task)) == toset(["worker", "bootstrap", "migrate"])
    error_message = "The legacy runtime contract must retain the original jobs."
  }
}

run "noble_demo_uses_one_image_for_accounts_migration_and_admin" {
  command = plan
  variables {
    stage                   = "runtime"
    int_runtime_profile     = "demo-a"
    demo_a_acceptance_nonce = "test-prepare"
    demo_source_revision    = "1234567890123456789012345678901234567890"
    noble_postgres_from_run = true
    secret_versions         = { app_password = "12", migrator_password = "13", postgres_ca = "14", bootstrap_admin = "15" }
  }
  assert {
    condition = (
      google_cloud_run_v2_service.api[0].iap_enabled &&
      !google_cloud_run_v2_service.api[0].invoker_iam_disabled &&
      length(google_iap_web_cloud_run_service_iam_member.pilot_admin) == 0 &&
      length(google_iap_web_cloud_run_service_iam_member.deploy_acceptance) == 1 &&
      google_cloud_run_v2_service_iam_member.iap_invoker[0].member == "serviceAccount:service-816643438938@gcp-sa-iap.iam.gserviceaccount.com" &&
      contains(google_cloud_run_v2_service.api[0].template[0].containers[0].args, "app.int_demo:app") &&
      toset(keys(google_cloud_run_v2_job.task)) == toset(["migrate", "bootstrap"]) &&
      toset(keys(google_cloud_run_v2_job_iam_member.protected_operator)) == toset(["migrate", "bootstrap"]) &&
      length(google_cloud_run_v2_job_iam_member.api_worker) == 0 &&
      alltrue([for env in [google_cloud_run_v2_service.api[0].template[0].containers[0].env,
        google_cloud_run_v2_job.task["migrate"].template[0].template[0].containers[0].env,
        google_cloud_run_v2_job.task["bootstrap"].template[0].template[0].containers[0].env] : try(
        one([for item in env : item.value if item.name == "CLIPFORGE_DATABASE_HOST"]) == "10.80.1.3" &&
        one([for item in env : item.value if item.name == "CLIPFORGE_DATABASE_SSL_MODE"]) == "verify-full" &&
        one([for item in env : item.value if item.name == "CLIPFORGE_RUNTIME_PROFILE"]) == "int-demo-a" &&
        one([for item in env : item.value if item.name == "CLIPFORGE_STORAGE_BACKEND"]) == "local" &&
        !anytrue([for item in env : contains(["CLIPFORGE_GCS_BUCKET", "CLIPFORGE_CLOUD_JOB", "WHISPER_MODEL"], item.name)]),
      false)])
    )
    error_message = "The protected account demo must use one image for the API, migration and admin initializer."
  }
}

run "noble_demo_explicit_human_iap_binding_uses_exact_service" {
  command = plan
  variables {
    stage                    = "runtime"
    int_runtime_profile      = "demo-a"
    demo_a_acceptance_nonce  = "test-human"
    demo_source_revision     = "1234567890123456789012345678901234567890"
    noble_postgres_from_run  = true
    demo_a_iap_human_enabled = true
    secret_versions          = { app_password = "12", migrator_password = "13", postgres_ca = "14", bootstrap_admin = "15" }
  }
  assert {
    condition = (
      google_cloud_run_v2_service.api[0].iap_enabled &&
      !google_cloud_run_v2_service.api[0].invoker_iam_disabled &&
      google_iap_web_cloud_run_service_iam_member.pilot_admin[0].cloud_run_service_name == "clipforge-int-api" &&
      google_iap_web_cloud_run_service_iam_member.pilot_admin[0].member == "user:admin@ixbalam.studio" &&
      google_iap_web_cloud_run_service_iam_member.pilot_admin[0].role == "roles/iap.httpsResourceAccessor" &&
      google_iap_web_cloud_run_service_iam_member.deploy_acceptance[0].member == "serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com" &&
      google_iap_web_cloud_run_service_iam_member.deploy_acceptance[0].role == "roles/iap.httpsResourceAccessor" &&
      google_secret_manager_secret_iam_member.bootstrap_admin_human[0].secret_id == "clipforge-int-bootstrap-admin" &&
      google_secret_manager_secret_iam_member.bootstrap_admin_human[0].role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.bootstrap_admin_human[0].member == "user:admin@ixbalam.studio"
    )
    error_message = "The second demo phase must retain protected IAP and add only the exact human member."
  }
}

run "noble_demo_fails_without_bound_source_revision" {
  command = plan
  variables {
    stage                   = "runtime"
    int_runtime_profile     = "demo-a"
    demo_a_acceptance_nonce = "test-invalid-source"
    noble_postgres_from_run = true
    secret_versions         = { app_password = "12", migrator_password = "13", postgres_ca = "14", bootstrap_admin = "15" }
  }
  expect_failures = [var.int_runtime_profile]
}
