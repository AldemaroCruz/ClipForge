variable "project_id" {
  type    = string
  default = "clipforgebeta2"
  validation {
    condition     = var.project_id == "clipforgebeta2"
    error_message = "TF-INT-01 is restricted to clipforgebeta2."
  }
}

variable "machine_type" {
  type    = string
  default = "e2-micro"
  validation {
    condition     = contains(["e2-micro", "e2-small"], var.machine_type)
    error_message = "Evaluate only the reviewed micro/small profiles; neither promises capacity."
  }
}

variable "run_subnet_cidr" {
  type    = string
  default = "10.80.0.0/26"
  validation {
    condition     = can(cidrnetmask(var.run_subnet_cidr)) && can(regex("^10\\.80\\.[0-9]+\\.0/(24|25|26)$", var.run_subnet_cidr))
    error_message = "Cloud Run Direct VPC requires a private dedicated /26 or larger subnet."
  }
}

variable "postgres_subnet_cidr" {
  type    = string
  default = "10.80.1.0/28"
  validation {
    condition     = can(cidrnetmask(var.postgres_subnet_cidr)) && can(regex("^10\\.80\\.[0-9]+\\.0/(24|25|26|27|28)$", var.postgres_subnet_cidr))
    error_message = "PostgreSQL must use the reviewed private 10.80.x.0 network range."
  }
}

variable "data_disk_gb" {
  type    = number
  default = 20
  validation {
    condition     = var.data_disk_gb >= 20 && var.data_disk_gb <= 200 && floor(var.data_disk_gb) == var.data_disk_gb
    error_message = "Data disk must be an integer from 20 to 200 GiB; shrinking an existing disk is not permitted."
  }
}

variable "runtime_image" {
  description = "Real reviewed OCI manifest digest; publication is a separately approved step."
  type        = string
  validation {
    condition     = can(regex("^us-central1-docker\\.pkg\\.dev/clipforgebeta2/clipforge-int/runtime@sha256:[0-9a-f]{64}$", var.runtime_image))
    error_message = "Use the exact runtime manifest digest in the existing INT repository, never a tag or image config ID."
  }
}

variable "secret_versions" {
  description = "Version numbers only; secret payloads must never enter Terraform."
  type = object({
    app_password      = string
    migrator_password = string
    postgres_ca       = string
    bootstrap_admin   = string
  })
  default = null
  validation {
    condition     = (var.stage == "foundation" && var.secret_versions == null) || try(alltrue([for version in values(var.secret_versions) : can(regex("^[1-9][0-9]*$", version))]), false)
    error_message = "Pin explicit Secret Manager version numbers; latest and secret values are forbidden."
  }
}

variable "stage" {
  description = "Foundation first; runtime needs published image, protected secret versions and a configured database. Each phase needs its own reviewed saved plan."
  type        = string
  default     = "foundation"
  validation {
    condition     = contains(["foundation", "runtime"], var.stage)
    error_message = "Only foundation and runtime phases exist; no targeting."
  }
}
