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
