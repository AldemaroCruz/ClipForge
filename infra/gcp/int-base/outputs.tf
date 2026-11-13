# No secrets, connection strings, full metadata or credentials are outputs.
output "reviewed_boundary" {
  value = {
    project_id     = data.google_project.existing.project_id
    project_number = data.google_project.existing.number
    region         = local.region
    vm_public_ip   = false
    cloud_run      = "deferred"
  }
}
