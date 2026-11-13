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
  project = var.project_id
  region  = "us-central1"
  zone    = "us-central1-a"
}
