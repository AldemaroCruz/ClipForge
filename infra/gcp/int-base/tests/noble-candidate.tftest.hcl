# Authored image and cloud identifiers. All runs use planning with a mock provider.
variables {
  runtime_image = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
  mock_data "google_service_account" {
    defaults = {
      email = "clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com"
      name  = "projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_service_account" {
    defaults = {
      email = "clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"
      name  = "projects/clipforgebeta2/serviceAccounts/clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"
    }
  }
}

override_data {
  target = data.google_project.existing
  values = { number = "816643438938" }
}

override_data {
  target = data.google_service_account.existing["deploy"]
  values = { email = "clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com" }
}

run "noble_is_opt_in" {
  command = plan

  assert {
    condition = (
      length(data.google_compute_image.noble) == 0 && length(google_service_account.noble) == 0 &&
      length(google_compute_address.noble) == 0 && length(google_compute_disk.noble_boot) == 0 &&
      length(google_compute_disk.noble_data) == 0 && length(google_compute_instance.noble) == 0 &&
      length(google_compute_firewall.noble_iap) == 0 && length(google_compute_firewall.noble_https) == 0 &&
      length(google_compute_firewall.noble_deny_egress) == 0 &&
      length(google_compute_instance_iam_member.noble_deploy) == 0 &&
      length(google_iap_tunnel_instance_iam_member.noble_deploy) == 0 &&
      length(google_service_account_iam_member.noble_deploy) == 0 &&
      output.db01_noble_candidate == null
    )
    error_message = "A default invocation must skip every Noble data read, resource, and output."
  }
  assert {
    condition     = google_compute_instance.postgres.name == "clipforge-int-base-postgres" && google_compute_address.postgres.address == "10.80.1.2"
    error_message = "The existing Debian VM name and address must remain unchanged by the new module source."
  }
}

run "noble_private_observation_graph" {
  command = plan
  variables {
    db01_noble_candidate = { image_name = "ubuntu-2404-noble-amd64-v20000101", image_id = "9000000000000000001" }
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
    target          = google_compute_instance.noble[0]
    override_during = plan
    values          = { instance_id = "9000000000000000002" }
  }
  override_resource {
    target          = google_compute_disk.noble_boot[0]
    override_during = plan
    values = {
      id              = "projects/clipforgebeta2/zones/us-central1-a/disks/clipforge-int-db01-noble-boot"
      disk_id         = "9000000000000000003"
      source_image_id = "9000000000000000001"
    }
  }
  override_resource {
    target          = google_compute_disk.noble_data[0]
    override_during = plan
    values = {
      id      = "projects/clipforgebeta2/zones/us-central1-a/disks/clipforge-int-db01-noble-data"
      disk_id = "9000000000000000004"
    }
  }
  override_resource {
    target          = google_compute_subnetwork.private["postgres"]
    override_during = plan
    values          = { id = "projects/clipforgebeta2/regions/us-central1/subnetworks/clipforge-int-base-postgres" }
  }
  assert {
    condition = (
      google_compute_instance.noble[0].name == "clipforge-int-db01-noble" &&
      google_compute_instance.noble[0].machine_type == "e2-small" &&
      google_compute_instance.noble[0].deletion_protection &&
      !google_compute_instance.noble[0].allow_stopping_for_update &&
      !google_compute_instance.noble[0].can_ip_forward &&
      google_compute_address.noble[0].address_type == "INTERNAL" &&
      google_compute_instance.noble[0].network_interface[0].network_ip == "10.80.1.3" &&
      google_compute_instance.noble[0].network_interface[0].subnetwork == google_compute_subnetwork.private["postgres"].id &&
      length(google_compute_instance.noble[0].network_interface[0].access_config) == 0 &&
      length(google_compute_instance.noble[0].network_interface[0].ipv6_access_config) == 0 &&
      google_compute_instance.noble[0].shielded_instance_config[0].enable_secure_boot
    )
    error_message = "The opt-in candidate must retain its exact isolated machine and private subnet."
  }
  assert {
    condition = (
      google_compute_disk.noble_boot[0].type == "pd-standard" && google_compute_disk.noble_boot[0].size == 10 &&
      google_compute_disk.noble_boot[0].image == data.google_compute_image.noble[0].self_link &&
      google_compute_disk.noble_data[0].type == "pd-standard" && google_compute_disk.noble_data[0].size == 20 &&
      google_compute_disk.noble_data[0].image == null &&
      google_compute_instance.noble[0].boot_disk[0].source == google_compute_disk.noble_boot[0].id &&
      !google_compute_instance.noble[0].boot_disk[0].auto_delete &&
      one(google_compute_instance.noble[0].attached_disk).source == google_compute_disk.noble_data[0].id &&
      one(google_compute_instance.noble[0].attached_disk).device_name == "clipforge-noble-pg-data" &&
      output.db01_noble_candidate.instance_id == google_compute_instance.noble[0].instance_id &&
      output.db01_noble_candidate.boot_disk_id == google_compute_disk.noble_boot[0].disk_id &&
      output.db01_noble_candidate.data_disk_id == google_compute_disk.noble_data[0].disk_id
    )
    error_message = "The pinned boot image and separate blank disk must have identifiable attachments and no boot auto-deletion."
  }
  assert {
    condition = (
      google_compute_instance.noble[0].service_account[0].email == google_service_account.noble[0].email &&
      toset(google_compute_instance.noble[0].service_account[0].scopes) == toset(["https://www.googleapis.com/auth/userinfo.email"]) &&
      google_compute_instance.noble[0].metadata["enable-oslogin"] == "TRUE" &&
      google_compute_instance.noble[0].metadata["block-project-ssh-keys"] == "TRUE" &&
      google_compute_instance.noble[0].metadata["serial-port-enable"] == "FALSE" &&
      google_compute_instance_iam_member.noble_deploy[0].instance_name == google_compute_instance.noble[0].name &&
      google_compute_instance_iam_member.noble_deploy[0].role == "roles/compute.osAdminLogin" &&
      google_iap_tunnel_instance_iam_member.noble_deploy[0].instance == google_compute_instance.noble[0].instance_id &&
      google_iap_tunnel_instance_iam_member.noble_deploy[0].role == "roles/iap.tunnelResourceAccessor" &&
      one(google_iap_tunnel_instance_iam_member.noble_deploy[0].condition).expression == "destination.port == 22" &&
      google_service_account_iam_member.noble_deploy[0].service_account_id == google_service_account.noble[0].name &&
      google_service_account_iam_member.noble_deploy[0].role == "roles/iam.serviceAccountUser" &&
      alltrue([
        for member in [
          google_compute_instance_iam_member.noble_deploy[0].member,
          google_iap_tunnel_instance_iam_member.noble_deploy[0].member,
          google_service_account_iam_member.noble_deploy[0].member,
        ] : member == "serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
      ])
    )
    error_message = "Only Deploy's scoped IAP, OS Login and SA attachment permissions should be proposed."
  }
  assert {
    condition = (
      toset(google_compute_firewall.noble_iap[0].source_ranges) == toset(["35.235.240.0/20"]) &&
      toset(one(google_compute_firewall.noble_iap[0].allow).ports) == toset(["22"]) &&
      toset(one(google_compute_firewall.noble_https[0].allow).ports) == toset(["443"]) &&
      one(google_compute_firewall.noble_deny_egress[0].deny).protocol == "all" &&
      alltrue([
        for rule in [
          google_compute_firewall.noble_iap[0].target_service_accounts,
          google_compute_firewall.noble_https[0].target_service_accounts,
          google_compute_firewall.noble_deny_egress[0].target_service_accounts,
        ] : toset(rule) == toset([google_service_account.noble[0].email])
      ]) &&
      substr(google_compute_instance.noble[0].metadata_startup_script, 0, 2) == "#!" &&
      sha256(google_compute_instance.noble[0].metadata_startup_script) == output.db01_noble_candidate.startup_sha256 &&
      can(regex("^[0-9a-f]{64}$", output.db01_noble_candidate.hostkey_nonce))
    )
    error_message = "Candidate firewall isolation and exact startup provenance are required."
  }
}

run "noble_rejects_moving_family" {
  command = plan
  variables {
    db01_noble_candidate = { image_name = "ubuntu-2404-lts-amd64", image_id = "9000000000000000001" }
  }
  expect_failures = [var.db01_noble_candidate]
}

run "noble_rejects_catalog_identity_change" {
  command = plan
  variables {
    db01_noble_candidate = { image_name = "ubuntu-2404-noble-amd64-v20000101", image_id = "9000000000000000001" }
  }
  override_data {
    target = data.google_compute_image.noble[0]
    values = {
      image_id     = "9000000000000000099"
      status       = "READY"
      family       = "ubuntu-2404-lts-amd64"
      self_link    = "https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20000101"
      licenses     = ["https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-2404-lts"]
      disk_size_gb = 10
    }
  }
  expect_failures = [data.google_compute_image.noble[0]]
}

run "noble_rejects_pro_license" {
  command = plan
  variables {
    db01_noble_candidate = { image_name = "ubuntu-2404-noble-amd64-v20000101", image_id = "9000000000000000001" }
  }
  override_data {
    target = data.google_compute_image.noble[0]
    values = {
      image_id     = "9000000000000000001"
      status       = "READY"
      family       = "ubuntu-2404-lts-amd64"
      self_link    = "https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20000101"
      licenses     = ["https://www.googleapis.com/compute/v1/projects/ubuntu-os-pro-cloud/global/licenses/ubuntu-pro-2404-lts"]
      disk_size_gb = 10
    }
  }
  expect_failures = [data.google_compute_image.noble[0]]
}
