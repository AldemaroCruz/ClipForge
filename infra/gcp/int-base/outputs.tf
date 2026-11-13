# No secrets, connection strings, full metadata or credentials are outputs.
output "reviewed_boundary" {
  value = {
    project_id     = data.google_project.existing.project_id
    project_number = data.google_project.existing.number
    region         = local.region
    vm_public_ip   = false
    stage          = var.stage
    cloud_run      = var.stage == "runtime" ? "built-in IAP; admin@ixbalam.studio; application auth remains required" : "separate runtime phase; no application service is created"
    runtime_image  = var.runtime_image
    encryption     = "Google-managed default proposed; five original key findings remain unaccepted"
    access_audit   = "GCS DATA_READ/WRITE; private pilot sink/view; 30-day retention"
  }
}
