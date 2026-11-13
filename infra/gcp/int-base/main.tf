locals {
  region = "us-central1"
  zone   = "us-central1-a"
  labels = { application = "clipforge", environment = "int", managed_by = "tf-int-01" }
  accounts = {
    terraform = "clipforge-terraform-int"
    deploy    = "clipforge-deploy-int"
    api       = "clipforge-api-int"
    worker    = "clipforge-worker-int"
    migrate   = "clipforge-migrate-int"
    postgres  = "clipforge-postgres-int"
  }
}

# Bootstrap retains ownership. These data sources never read secret versions.
data "google_project" "existing" { project_id = var.project_id }
data "google_storage_bucket" "state" { name = "clipforgebeta2-tfstate-int" }
data "google_artifact_registry_repository" "existing" {
  project       = var.project_id
  location      = local.region
  repository_id = "clipforge-int"
}
data "google_iam_workload_identity_pool_provider" "existing" {
  project                            = var.project_id
  workload_identity_pool_id          = "clipforge-gh-int"
  workload_identity_pool_provider_id = "github"
}
data "google_service_account" "existing" {
  for_each   = local.accounts
  project    = var.project_id
  account_id = each.value
}
data "google_secret_manager_secret" "existing" {
  for_each  = toset(["clipforge-int-pg-app-password", "clipforge-int-pg-migrator-password"])
  project   = var.project_id
  secret_id = each.value
}
data "google_compute_image" "debian" {
  project = "debian-cloud"
  family  = "debian-13"
}

resource "terraform_data" "boundary" {
  input = var.project_id
  lifecycle {
    precondition {
      condition     = tostring(data.google_project.existing.number) == "816643438938"
      error_message = "The selected project's number must match bootstrap."
    }
    precondition {
      condition     = cidrhost(var.run_subnet_cidr, 0) != cidrhost(var.postgres_subnet_cidr, 0)
      error_message = "Private subnet ranges must not overlap."
    }
  }
}

resource "google_compute_network" "int" {
  project                         = var.project_id
  name                            = "clipforge-int-base"
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = true
  depends_on                      = [terraform_data.boundary]
}
resource "google_compute_subnetwork" "private" {
  for_each                 = { run = var.run_subnet_cidr, postgres = var.postgres_subnet_cidr }
  project                  = var.project_id
  name                     = "clipforge-int-base-${each.key}"
  region                   = local.region
  network                  = google_compute_network.int.id
  ip_cidr_range            = each.value
  private_ip_google_access = true
  stack_type               = "IPV4_ONLY"
  log_config {
    aggregation_interval = "INTERVAL_30_SEC"
    flow_sampling        = 0.1
    metadata             = "EXCLUDE_ALL_METADATA"
  }
}
resource "google_compute_route" "egress" {
  project          = var.project_id
  name             = "clipforge-int-base-egress"
  network          = google_compute_network.int.name
  dest_range       = "0.0.0.0/0"
  next_hop_gateway = "default-internet-gateway"
  priority         = 1000
}
resource "google_compute_router" "egress" {
  project = var.project_id
  name    = "clipforge-int-base-egress"
  region  = local.region
  network = google_compute_network.int.id
}
resource "google_compute_router_nat" "maintenance" {
  project                            = var.project_id
  name                               = "clipforge-int-base-maintenance"
  region                             = local.region
  router                             = google_compute_router.egress.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = google_compute_subnetwork.private["postgres"].id
    source_ip_ranges_to_nat = ["PRIMARY_IP_RANGE"]
  }
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
resource "google_compute_address" "postgres" {
  project      = var.project_id
  name         = "clipforge-int-base-postgres"
  region       = local.region
  address_type = "INTERNAL"
  subnetwork   = google_compute_subnetwork.private["postgres"].id
  address      = cidrhost(var.postgres_subnet_cidr, 2)
}

resource "google_compute_firewall" "postgres" {
  project                 = var.project_id
  name                    = "clipforge-int-base-pg-from-run"
  network                 = google_compute_network.int.name
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = [var.run_subnet_cidr]
  target_service_accounts = [data.google_service_account.existing["postgres"].email]
  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
  log_config { metadata = "EXCLUDE_ALL_METADATA" }
}
resource "google_compute_firewall" "iap" {
  project                 = var.project_id
  name                    = "clipforge-int-base-iap-ssh"
  network                 = google_compute_network.int.name
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = ["35.235.240.0/20"]
  target_service_accounts = [data.google_service_account.existing["postgres"].email]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  log_config { metadata = "EXCLUDE_ALL_METADATA" }
}
resource "google_compute_firewall" "https" {
  project                 = var.project_id
  name                    = "clipforge-int-base-maintenance-https"
  network                 = google_compute_network.int.name
  direction               = "EGRESS"
  priority                = 1000
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = [data.google_service_account.existing["postgres"].email]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  log_config { metadata = "EXCLUDE_ALL_METADATA" }
}
resource "google_compute_firewall" "deny_egress" {
  project                 = var.project_id
  name                    = "clipforge-int-base-deny-other-egress"
  network                 = google_compute_network.int.name
  direction               = "EGRESS"
  priority                = 65534
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = [data.google_service_account.existing["postgres"].email]
  deny { protocol = "all" }
  log_config { metadata = "EXCLUDE_ALL_METADATA" }
}

resource "google_compute_disk" "postgres" {
  project = var.project_id
  name    = "clipforge-int-base-postgres-data"
  zone    = local.zone
  type    = "pd-standard"
  size    = var.data_disk_gb
  labels  = local.labels
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.boundary]
}
resource "google_compute_instance" "postgres" {
  project                   = var.project_id
  name                      = "clipforge-int-base-postgres"
  zone                      = local.zone
  machine_type              = var.machine_type
  deletion_protection       = true
  allow_stopping_for_update = false
  can_ip_forward            = false
  labels                    = local.labels
  boot_disk {
    auto_delete = false
    initialize_params {
      image = data.google_compute_image.debian.self_link
      size  = 10
      type  = "pd-standard"
    }
  }
  attached_disk {
    source      = google_compute_disk.postgres.id
    device_name = "clipforge-pg-data"
  }
  network_interface {
    subnetwork = google_compute_subnetwork.private["postgres"].id
    network_ip = google_compute_address.postgres.address
    # No access_config or ipv6_access_config: no public VM address.
  }
  service_account {
    email  = data.google_service_account.existing["postgres"].email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  metadata = {
    enable-oslogin           = "TRUE"
    block-project-ssh-keys   = "TRUE"
    disable-legacy-endpoints = "TRUE"
    serial-port-enable       = "FALSE"
  }
  metadata_startup_script = file("${path.module}/postgres-install.sh")
  lifecycle { prevent_destroy = true }
  depends_on = [google_compute_router_nat.maintenance, google_compute_firewall.deny_egress]
}

resource "google_storage_bucket" "private" {
  for_each                    = toset(["media", "backups"])
  project                     = var.project_id
  name                        = "clipforgebeta2-int-${each.key}"
  location                    = local.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = merge(local.labels, { purpose = each.key })
  versioning { enabled = true }
  retention_policy {
    retention_period = each.key == "backups" ? 2592000 : 604800
    is_locked        = false
  }
  soft_delete_policy { retention_duration_seconds = 604800 }
  lifecycle_rule {
    condition {
      days_since_noncurrent_time = 30
      num_newer_versions         = 3
      with_state                 = "ARCHIVED"
    }
    action { type = "Delete" }
  }
  dynamic "lifecycle_rule" {
    for_each = each.key == "backups" ? [1] : []
    content {
      condition {
        age        = 90
        with_state = "LIVE"
      }
      action { type = "Delete" }
    }
  }
  lifecycle { prevent_destroy = true }
  depends_on = [terraform_data.boundary]
}
