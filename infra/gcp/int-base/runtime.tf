# INT-E2E-01 proposal only. No public principal, KMS/CSEK, service-account key,
# secret payload, or service-identity data source is introduced by this root.
locals {
  runtime_accounts = { api = "api", worker = "worker", migrate = "migrate", bootstrap = "migrate" }
  runtime_secrets = {
    app_password      = "clipforge-int-pg-app-password"
    migrator_password = "clipforge-int-pg-migrator-password"
    postgres_ca       = google_secret_manager_secret.runtime["postgres-ca"].secret_id
    bootstrap_admin   = google_secret_manager_secret.runtime["bootstrap-admin"].secret_id
  }
  common_env = {
    CLIPFORGE_DATABASE_POOL_SIZE          = "2"
    CLIPFORGE_DATABASE_POOL_OVERFLOW      = "1"
    CLIPFORGE_ENVIRONMENT                 = "int"
    MAX_UPLOAD_MB                         = "30"
    CLIPFORGE_STORAGE_BACKEND             = "gcs"
    CLIPFORGE_GCS_BUCKET                  = google_storage_bucket.private["media"].name
    CLIPFORGE_CLOUD_PROJECT               = var.project_id
    CLIPFORGE_CLOUD_REGION                = local.region
    CLIPFORGE_CLOUD_JOB                   = "clipforge-int-worker"
    CLIPFORGE_DATABASE_HOST               = "10.80.1.2"
    CLIPFORGE_DATABASE_PORT               = "5432"
    CLIPFORGE_DATABASE_NAME               = "clipforge"
    CLIPFORGE_DATABASE_SSL_MODE           = "verify-full"
    CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE = "/secrets/postgres-ca/value"
    CLIPFORGE_ALLOW_INSECURE_HTTP         = "0"
    CLIPFORGE_LLM_ENABLED                 = "0"
    WHISPER_MODEL                         = "tiny"
    HF_HOME                               = "/opt/clipforge/models"
    CLIPFORGE_MODEL_LOCK                  = "/opt/clipforge/whisper-int.json"
    HF_HUB_OFFLINE                        = "1"
    CLIPFORGE_AUTH_PROFILE                = "https"
    CLIPFORGE_AUTH_ORIGIN                 = "https://clipforge-int-api-816643438938.us-central1.run.app"
  }
  job_commands = {
    worker    = ["-m", "app.cloud.worker"]
    migrate   = ["-m", "app.cloud.migrate"]
    bootstrap = ["-m", "app.cloud.bootstrap_admin"]
  }
}

# Containers only: payload versions are written later by a protected workflow.
resource "google_secret_manager_secret" "runtime" {
  for_each  = toset(["postgres-ca", "bootstrap-admin"])
  project   = var.project_id
  secret_id = "clipforge-int-${each.key}"
  labels    = local.labels
  replication {
    auto {}
  }
  lifecycle { prevent_destroy = true }
}

resource "google_secret_manager_secret_iam_member" "runtime" {
  for_each = {
    api_password     = { account = "api", secret = "app_password" }
    worker_password  = { account = "worker", secret = "app_password" }
    migrate_password = { account = "migrate", secret = "migrator_password" }
    api_ca           = { account = "api", secret = "postgres_ca" }
    worker_ca        = { account = "worker", secret = "postgres_ca" }
    migrate_ca       = { account = "migrate", secret = "postgres_ca" }
    bootstrap_admin  = { account = "migrate", secret = "bootstrap_admin" }
  }
  project   = var.project_id
  secret_id = local.runtime_secrets[each.value.secret]
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${data.google_service_account.existing[each.value.account].email}"
}

resource "google_storage_bucket_iam_member" "media" {
  for_each = toset(["api", "worker"])
  bucket   = google_storage_bucket.private["media"].name
  role     = "roles/storage.objectUser"
  member   = "serviceAccount:${data.google_service_account.existing[each.key].email}"
}

resource "google_storage_bucket_iam_member" "backup_writer" {
  bucket = google_storage_bucket.private["backups"].name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${data.google_service_account.existing["postgres"].email}"
}

# Additional pipeline privileges are proposals for the owner to review. Bootstrap
# currently proves authentication, not permission to publish these versions.
resource "google_secret_manager_secret_iam_member" "version_publisher" {
  for_each  = local.runtime_secrets
  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretVersionAdder"
  member    = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
}
resource "google_compute_instance_iam_member" "protected_bootstrap" {
  project       = var.project_id
  zone          = local.zone
  instance_name = google_compute_instance.postgres.name
  role          = "roles/compute.osAdminLogin"
  member        = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
}
resource "google_iap_tunnel_instance_iam_member" "protected_bootstrap" {
  project  = var.project_id
  zone     = local.zone
  instance = google_compute_instance.postgres.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
}
resource "google_service_account_iam_member" "protected_bootstrap" {
  service_account_id = data.google_service_account.existing["postgres"].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
}
resource "google_project_iam_custom_role" "bootstrap_reader" {
  project     = var.project_id
  role_id     = "clipforgeIntBootstrapReader"
  title       = "INT bootstrap metadata reader"
  description = "Four metadata GET operations: fixed VM/disk bootstrap and observing protected Job completion; no lists/writes."
  permissions = ["compute.instances.get", "compute.disks.get", "compute.projects.get", "run.operations.get"]
}
resource "google_project_iam_member" "bootstrap_reader" {
  project = var.project_id
  role    = google_project_iam_custom_role.bootstrap_reader.name
  member  = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
}

resource "google_cloud_run_v2_service" "api" {
  count               = var.stage == "runtime" ? 1 : 0
  project             = var.project_id
  name                = "clipforge-int-api"
  location            = local.region
  deletion_protection = true
  ingress             = "INGRESS_TRAFFIC_ALL"
  iap_enabled         = true
  labels              = local.labels
  template {
    service_account                  = data.google_service_account.existing["api"].email
    max_instance_request_concurrency = 8
    timeout                          = "300s"
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.int.name
        subnetwork = google_compute_subnetwork.private["run"].name
      }
    }
    containers {
      image   = var.runtime_image
      command = ["python"]
      args    = ["-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips=*"]
      resources {
        limits            = { cpu = "1", memory = "1Gi" }
        cpu_idle          = true
        startup_cpu_boost = false
      }
      dynamic "env" {
        for_each = merge(local.common_env, {
          CLIPFORGE_DATABASE_USER          = "clipforge_app"
          CLIPFORGE_DATABASE_PASSWORD_FILE = "/secrets/database/value"
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      volume_mounts {
        name       = "database"
        mount_path = "/secrets/database"
      }
      volume_mounts {
        name       = "postgres-ca"
        mount_path = "/secrets/postgres-ca"
      }
    }
    volumes {
      name = "database"
      secret {
        secret = local.runtime_secrets.app_password
        items {
          version = var.secret_versions.app_password
          path    = "value"
        }
      }
    }
    volumes {
      name = "postgres-ca"
      secret {
        secret = local.runtime_secrets.postgres_ca
        items {
          version = var.secret_versions.postgres_ca
          path    = "value"
        }
      }
    }
  }
  depends_on = [google_secret_manager_secret_iam_member.runtime]
}

# Built-in IAP protects the run.app address without a new load balancer.
# The IAP service agent is created by enabling IAP at apply, never by a data read.
resource "google_cloud_run_v2_service_iam_member" "iap_invoker" {
  count    = var.stage == "runtime" ? 1 : 0
  project  = var.project_id
  location = local.region
  name     = google_cloud_run_v2_service.api[0].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:service-816643438938@gcp-sa-iap.iam.gserviceaccount.com"
}
resource "google_iap_web_cloud_run_service_iam_member" "pilot_admin" {
  count                  = var.stage == "runtime" ? 1 : 0
  project                = var.project_id
  location               = local.region
  cloud_run_service_name = google_cloud_run_v2_service.api[0].name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = "user:admin@ixbalam.studio"
}

resource "google_cloud_run_v2_job" "task" {
  for_each            = var.stage == "runtime" ? local.job_commands : {}
  project             = var.project_id
  name                = "clipforge-int-${each.key}"
  location            = local.region
  deletion_protection = true
  labels              = local.labels
  template {
    task_count  = 1
    parallelism = 1
    template {
      service_account       = data.google_service_account.existing[local.runtime_accounts[each.key]].email
      max_retries           = 0
      timeout               = each.key == "worker" ? "3600s" : "600s"
      execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = google_compute_network.int.name
          subnetwork = google_compute_subnetwork.private["run"].name
        }
      }
      containers {
        image   = var.runtime_image
        command = ["python"]
        args    = each.value
        resources { limits = each.key == "worker" ? { cpu = "2", memory = "4Gi" } : { cpu = "1", memory = "1Gi" } }
        dynamic "env" {
          for_each = merge(local.common_env, {
            CLIPFORGE_DATABASE_USER          = each.key == "worker" ? "clipforge_app" : "clipforge_migrator"
            CLIPFORGE_DATABASE_PASSWORD_FILE = "/secrets/database/value"
          }, each.key == "bootstrap" ? { CLIPFORGE_BOOTSTRAP_ADMIN_FILE = "/secrets/admin/value" } : {})
          content {
            name  = env.key
            value = env.value
          }
        }
        volume_mounts {
          name       = "database"
          mount_path = "/secrets/database"
        }
        volume_mounts {
          name       = "postgres-ca"
          mount_path = "/secrets/postgres-ca"
        }
        dynamic "volume_mounts" {
          for_each = each.key == "bootstrap" ? [1] : []
          content {
            name       = "admin"
            mount_path = "/secrets/admin"
          }
        }
      }
      volumes {
        name = "database"
        secret {
          secret = each.key == "worker" ? local.runtime_secrets.app_password : local.runtime_secrets.migrator_password
          items {
            version = each.key == "worker" ? var.secret_versions.app_password : var.secret_versions.migrator_password
            path    = "value"
          }
        }
      }
      volumes {
        name = "postgres-ca"
        secret {
          secret = local.runtime_secrets.postgres_ca
          items {
            version = var.secret_versions.postgres_ca
            path    = "value"
          }
        }
      }
      dynamic "volumes" {
        for_each = each.key == "bootstrap" ? [1] : []
        content {
          name = "admin"
          secret {
            secret = local.runtime_secrets.bootstrap_admin
            items {
              version = var.secret_versions.bootstrap_admin
              path    = "value"
            }
          }
        }
      }
    }
  }
  depends_on = [google_secret_manager_secret_iam_member.runtime]
}
resource "google_cloud_run_v2_job_iam_member" "api_worker" {
  count    = var.stage == "runtime" ? 1 : 0
  project  = var.project_id
  location = local.region
  name     = google_cloud_run_v2_job.task["worker"].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${data.google_service_account.existing["api"].email}"
}

resource "google_cloud_run_v2_job_iam_member" "protected_operator" {
  for_each = var.stage == "runtime" ? local.job_commands : {}
  project  = var.project_id
  location = local.region
  name     = google_cloud_run_v2_job.task[each.key].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
}
