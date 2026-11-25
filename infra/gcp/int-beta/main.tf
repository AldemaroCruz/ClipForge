terraform {
  required_version = "= 1.15.8"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 8.11.0"
    }
  }
  backend "gcs" {}
}

provider "google" {
  project = local.project
  region  = local.region
}

variable "web_image" {
  type = string
  validation {
    condition     = can(regex("^us-central1-docker\\.pkg\\.dev/clipforgebeta2/clipforge-int/beta-web@sha256:[0-9a-f]{64}$", var.web_image))
    error_message = "The web image must be digest-pinned in the dedicated INT repository."
  }
}

variable "worker_image" {
  type = string
  validation {
    condition     = can(regex("^us-central1-docker\\.pkg\\.dev/clipforgebeta2/clipforge-int/beta-worker@sha256:[0-9a-f]{64}$", var.worker_image))
    error_message = "The worker image must be digest-pinned in the dedicated INT repository."
  }
}

variable "source_revision" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.source_revision))
    error_message = "An exact GitHub source commit is required."
  }
}

variable "serve_public" {
  description = "Enable the public frontend after deploying the private components and migrating."
  type        = bool
  default     = false
}

variable "acceptance_nonce" {
  description = "Non-secret marker for a controlled frontend/API replacement."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,62}$", var.acceptance_nonce))
    error_message = "A bounded rollout marker is required."
  }
}

locals {
  project           = "clipforgebeta2"
  region            = "us-central1"
  api_service       = "clipforge-int-beta-api"
  frontend_service  = "clipforge-int-beta"
  worker_job        = "clipforge-int-worker"
  migrate_job       = "clipforge-int-beta-migrate"
  public_origin     = "https://clipforge-int-beta-816643438938.us-central1.run.app"
  frontend_identity = "clipforge-frontend-int@${local.project}.iam.gserviceaccount.com"
  api_identity      = "clipforge-api-int@${local.project}.iam.gserviceaccount.com"
  worker_identity   = "clipforge-worker-int@${local.project}.iam.gserviceaccount.com"
  migrator_identity = "clipforge-migrate-int@${local.project}.iam.gserviceaccount.com"
  deploy_identity   = "clipforge-deploy-int@${local.project}.iam.gserviceaccount.com"
  credentials = {
    application = "clipforge-int-pg-app-password"
    migrator    = "clipforge-int-pg-migrator-password"
  }
  database = {
    CLIPFORGE_ENVIRONMENT                 = "INT"
    CLIPFORGE_REVISION                    = var.source_revision
    CLIPFORGE_DATABASE_HOST               = "10.80.1.3"
    CLIPFORGE_DATABASE_PORT               = "5432"
    CLIPFORGE_DATABASE_NAME               = "clipforge"
    CLIPFORGE_DATABASE_SSL_MODE           = "verify-full"
    CLIPFORGE_DATABASE_PASSWORD_FILE      = "/secrets/database/value"
    CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE = "/secrets/postgres-ca/value"
    CLIPFORGE_DATABASE_POOL_SIZE          = "2"
    CLIPFORGE_DATABASE_POOL_OVERFLOW      = "1"
    CLIPFORGE_AUTH_PROFILE                = "https"
    CLIPFORGE_AUTH_ORIGIN                 = local.public_origin
    CLIPFORGE_ALLOW_INSECURE_HTTP         = "0"
  }
  cloud = {
    CLIPFORGE_STORAGE_BACKEND = "gcs"
    CLIPFORGE_GCS_BUCKET      = "clipforgebeta2-int-media"
    CLIPFORGE_CLOUD_PROJECT   = local.project
    CLIPFORGE_CLOUD_REGION    = local.region
    CLIPFORGE_CLOUD_JOB       = local.worker_job
    CLIPFORGE_AI_PROVIDER     = "disabled"
    CLIPFORGE_LLM_ENABLED     = "0"
    CLIPFORGE_INT_BETA        = "1"
  }
}

resource "google_cloud_run_v2_service" "api" {
  name                 = local.api_service
  location             = local.region
  deletion_protection  = true
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = false
  iap_enabled          = false
  custom_audiences     = ["https://clipforge-int-beta-api-816643438938.us-central1.run.app"]
  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
  template {
    service_account                  = local.api_identity
    timeout                          = "180s"
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    max_instance_request_concurrency = 8
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = "clipforge-int-base"
        subnetwork = "clipforge-int-base-run"
      }
    }
    containers {
      image   = var.web_image
      command = ["python"]
      args    = ["-m", "uvicorn", "app.int_beta:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--no-proxy-headers"]
      resources {
        limits   = { cpu = "1", memory = "512Mi" }
        cpu_idle = true
      }
      dynamic "env" {
        for_each = merge(local.database, local.cloud, {
          CLIPFORGE_DATABASE_USER    = "clipforge_app"
          CLIPFORGE_ACCEPTANCE_NONCE = var.acceptance_nonce
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
    dynamic "volumes" {
      for_each = { database = local.credentials.application, postgres-ca = "clipforge-int-postgres-ca" }
      content {
        name = volumes.key
        secret {
          secret = volumes.value
          items {
            version = "1"
            path    = "value"
          }
        }
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "frontend_invokes_api" {
  project  = local.project
  location = local.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${local.frontend_identity}"
}

resource "google_cloud_run_v2_service" "frontend" {
  name                 = local.frontend_service
  location             = local.region
  deletion_protection  = true
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = var.serve_public
  iap_enabled          = false
  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
  template {
    service_account                  = local.frontend_identity
    timeout                          = "180s"
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    max_instance_request_concurrency = 8
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    containers {
      image   = var.web_image
      command = ["python"]
      args    = ["-m", "uvicorn", "app.int_beta_proxy:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--no-proxy-headers"]
      resources {
        limits   = { cpu = "1", memory = "512Mi" }
        cpu_idle = true
      }
      env {
        name  = "CLIPFORGE_ACCEPTANCE_NONCE"
        value = var.acceptance_nonce
      }
    }
  }
  depends_on = [google_cloud_run_v2_service_iam_member.frontend_invokes_api]
}

resource "google_cloud_run_v2_job" "task" {
  for_each = {
    worker = {
      name  = local.worker_job, identity = local.worker_identity, credential = local.credentials.application
      image = var.worker_image, args = ["-m", "app.cloud.worker"], cpu = "2", memory = "4Gi", timeout = "1200s"
      user  = "clipforge_app", extra = local.cloud
    }
    migrate = {
      name  = local.migrate_job, identity = local.migrator_identity, credential = local.credentials.migrator
      image = var.web_image, args = ["-m", "app.cloud.migrate_beta"], cpu = "1", memory = "512Mi", timeout = "600s"
      user  = "clipforge_migrator", extra = {}
    }
  }
  name                = each.value.name
  location            = local.region
  deletion_protection = true
  template {
    task_count  = 1
    parallelism = 1
    template {
      service_account = each.value.identity
      max_retries     = 0
      timeout         = each.value.timeout
      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = "clipforge-int-base"
          subnetwork = "clipforge-int-base-run"
        }
      }
      containers {
        image   = each.value.image
        command = ["python"]
        args    = each.value.args
        resources { limits = { cpu = each.value.cpu, memory = each.value.memory } }
        dynamic "env" {
          for_each = merge(local.database, each.value.extra, { CLIPFORGE_DATABASE_USER = each.value.user })
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
      dynamic "volumes" {
        for_each = { database = each.value.credential, postgres-ca = "clipforge-int-postgres-ca" }
        content {
          name = volumes.key
          secret {
            secret = volumes.value
            items {
              version = "1"
              path    = "value"
            }
          }
        }
      }
    }
  }
}

resource "google_cloud_run_v2_job_iam_member" "api_invokes_worker" {
  project  = local.project
  location = local.region
  name     = google_cloud_run_v2_job.task["worker"].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${local.api_identity}"
}

resource "google_cloud_run_v2_job_iam_member" "deploy_invokes_migrate" {
  project  = local.project
  location = local.region
  name     = google_cloud_run_v2_job.task["migrate"].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${local.deploy_identity}"
}
