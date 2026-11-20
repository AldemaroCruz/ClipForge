# DB-01-NOBLE-PLAN. This optional graph has no effect at the default null input.
variable "db01_noble_candidate" {
  description = "Exact standard Noble GCE image observed in the public catalog for this plan."
  type = object({
    image_name = string
    image_id   = string
  })
  default = null

  validation {
    condition = var.db01_noble_candidate == null || try(
      var.stage == "foundation" && var.postgres_subnet_cidr == "10.80.1.0/28" &&
      can(regex("^ubuntu-2404-noble-amd64-v[0-9]{8}[a-z]?$", var.db01_noble_candidate.image_name)) &&
      can(regex("^[1-9][0-9]*$", var.db01_noble_candidate.image_id)), false
    )
    error_message = "Use the reviewed foundation subnet and an exact standard Ubuntu 24.04 amd64 image name and numeric ID."
  }
}

locals {
  noble_count   = var.db01_noble_candidate == null ? 0 : 1
  noble_name    = "clipforge-int-db01-noble"
  noble_ip      = "10.80.1.3"
  noble_labels  = merge(local.labels, { purpose = "db01-noble" })
  noble_license = "https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-2404-lts"
  noble_hostkey_nonce = local.noble_count == 0 ? null : sha256(jsonencode({
    project          = var.project_id
    project_number   = "816643438938"
    zone             = local.zone
    instance_name    = local.noble_name
    image_name       = var.db01_noble_candidate.image_name
    image_id         = var.db01_noble_candidate.image_id
    startup_sha256   = filesha256("${path.module}/db01-noble-startup.sh")
    legacy_sha256    = filesha256("${path.module}/../../../scripts/int_vm_hostkey_guest.py")
    publisher_sha256 = filesha256("${path.module}/../../../scripts/int_noble_hostkey.py")
    template_sha256  = filesha256("${path.module}/db01-noble-hostkey-template.sh")
  }))
  noble_startup = local.noble_count == 0 ? null : join("\n", [
    file("${path.module}/db01-noble-startup.sh"),
    templatefile("${path.module}/db01-noble-hostkey-template.sh", {
      nonce     = local.noble_hostkey_nonce
      legacy    = filebase64("${path.module}/../../../scripts/int_vm_hostkey_guest.py")
      publisher = filebase64("${path.module}/../../../scripts/int_noble_hostkey.py")
    }),
  ])
}

data "google_compute_image" "noble" {
  count   = local.noble_count
  project = "ubuntu-os-cloud"
  name    = var.db01_noble_candidate.image_name

  lifecycle {
    postcondition {
      condition = (
        self.name == var.db01_noble_candidate.image_name &&
        self.image_id == var.db01_noble_candidate.image_id &&
        self.status == "READY" &&
        self.family == "ubuntu-2404-lts-amd64" &&
        self.self_link == "https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/${var.db01_noble_candidate.image_name}" &&
        toset(self.licenses) == toset([local.noble_license]) &&
        self.disk_size_gb > 0 && self.disk_size_gb <= 10
      )
      error_message = "Noble must match the reviewed immutable catalog identity, standard license, and 10 GiB boot profile."
    }
  }
}

resource "google_service_account" "noble" {
  count        = local.noble_count
  project      = var.project_id
  account_id   = "clipforge-db01-noble-int"
  display_name = "INT DB-01 Noble candidate"
  description  = "Dedicated guest identity for the isolated Noble candidate and its firewall targets."
}

resource "google_compute_address" "noble" {
  count        = local.noble_count
  project      = var.project_id
  name         = local.noble_name
  region       = local.region
  address_type = "INTERNAL"
  subnetwork   = google_compute_subnetwork.private["postgres"].id
  address      = local.noble_ip
}

resource "google_compute_disk" "noble_boot" {
  count   = local.noble_count
  project = var.project_id
  name    = "${local.noble_name}-boot"
  zone    = local.zone
  type    = "pd-standard"
  size    = 10
  image   = data.google_compute_image.noble[count.index].self_link
  labels  = local.noble_labels

  lifecycle {
    prevent_destroy = true
    postcondition {
      condition     = self.source_image_id == var.db01_noble_candidate.image_id
      error_message = "Compute must report the exact pinned source image ID for the new boot disk."
    }
  }
}

resource "google_compute_disk" "noble_data" {
  count   = local.noble_count
  project = var.project_id
  name    = "${local.noble_name}-data"
  zone    = local.zone
  type    = "pd-standard"
  size    = 20
  labels  = local.noble_labels

  lifecycle { prevent_destroy = true }
}

resource "google_compute_firewall" "noble_iap" {
  count                   = local.noble_count
  project                 = var.project_id
  name                    = "${local.noble_name}-iap-ssh"
  network                 = google_compute_network.int.name
  direction               = "INGRESS"
  priority                = 1000
  source_ranges           = ["35.235.240.0/20"]
  target_service_accounts = [google_service_account.noble[count.index].email]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  log_config { metadata = "EXCLUDE_ALL_METADATA" }
}

resource "google_compute_firewall" "noble_https" {
  count                   = local.noble_count
  project                 = var.project_id
  name                    = "${local.noble_name}-https"
  network                 = google_compute_network.int.name
  direction               = "EGRESS"
  priority                = 1000
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = [google_service_account.noble[count.index].email]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  log_config { metadata = "EXCLUDE_ALL_METADATA" }
}

resource "google_compute_firewall" "noble_deny_egress" {
  count                   = local.noble_count
  project                 = var.project_id
  name                    = "${local.noble_name}-deny-egress"
  network                 = google_compute_network.int.name
  direction               = "EGRESS"
  priority                = 65534
  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = [google_service_account.noble[count.index].email]
  deny { protocol = "all" }
  log_config { metadata = "EXCLUDE_ALL_METADATA" }
}

resource "google_compute_instance" "noble" {
  count                     = local.noble_count
  project                   = var.project_id
  name                      = local.noble_name
  zone                      = local.zone
  machine_type              = "e2-small"
  deletion_protection       = true
  allow_stopping_for_update = false
  can_ip_forward            = false
  labels                    = local.noble_labels

  boot_disk {
    source      = google_compute_disk.noble_boot[count.index].id
    device_name = "clipforge-noble-pg-boot"
    auto_delete = false
  }
  attached_disk {
    source      = google_compute_disk.noble_data[count.index].id
    device_name = "clipforge-noble-pg-data"
  }
  network_interface {
    subnetwork = google_compute_subnetwork.private["postgres"].id
    network_ip = google_compute_address.noble[count.index].address
  }
  service_account {
    email  = google_service_account.noble[count.index].email
    scopes = ["https://www.googleapis.com/auth/userinfo.email"]
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
  metadata_startup_script = local.noble_startup
  lifecycle { prevent_destroy = true }
  depends_on = [
    google_compute_router_nat.maintenance,
    google_compute_firewall.noble_iap,
    google_compute_firewall.noble_https,
    google_compute_firewall.noble_deny_egress,
  ]
}

resource "google_compute_instance_iam_member" "noble_deploy" {
  count         = local.noble_count
  project       = var.project_id
  zone          = local.zone
  instance_name = google_compute_instance.noble[count.index].name
  role          = "roles/compute.osAdminLogin"
  member        = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
}

resource "google_iap_tunnel_instance_iam_member" "noble_deploy" {
  count    = local.noble_count
  project  = data.google_project.existing.number
  zone     = local.zone
  instance = google_compute_instance.noble[count.index].instance_id
  role     = "roles/iap.tunnelResourceAccessor"
  member   = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
  condition {
    title      = "db01_noble_ssh_only"
    expression = "destination.port == 22"
  }
}

resource "google_service_account_iam_member" "noble_deploy" {
  count              = local.noble_count
  service_account_id = google_service_account.noble[count.index].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_service_account.existing["deploy"].email}"
}

# Numeric IDs come from Compute after creation and are cross-checked with API
# reads, the attachment and the guest's restricted disk observation.
output "db01_noble_candidate" {
  value = local.noble_count == 0 ? null : {
    instance_name  = google_compute_instance.noble[0].name
    instance_id    = google_compute_instance.noble[0].instance_id
    boot_disk      = google_compute_disk.noble_boot[0].name
    boot_disk_id   = google_compute_disk.noble_boot[0].disk_id
    data_disk      = google_compute_disk.noble_data[0].name
    data_disk_id   = google_compute_disk.noble_data[0].disk_id
    data_device    = "clipforge-noble-pg-data"
    private_ip     = google_compute_address.noble[0].address
    service_email  = google_service_account.noble[0].email
    image_name     = data.google_compute_image.noble[0].name
    image_id       = data.google_compute_image.noble[0].image_id
    hostkey_nonce  = local.noble_hostkey_nonce
    startup_sha256 = sha256(local.noble_startup)
  }
}
