# Hardened GCS bucket for Terraform remote state.

terraform {
  required_version = ">= 1.10"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 8.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "project_id" { type = string }
variable "location" { type = string }
variable "prefix" { type = string }
variable "labels" {
  type    = map(string)
  default = {}
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  # Cloud Storage refuses bucket names that start with "goog" or contain "google" (or a close misspelling such as
  # "g00gle"): such a prefix gets a neutral stem from its hash. No bucket with such a name can exist, so no existing
  # environment's bucket is renamed.
  google_like = startswith(lower(var.prefix), "goog") || can(regex("g[o0]{2,}g[l1]e", lower(var.prefix)))
  # bucket names are at most 63 characters: "<prefix>-tfstate-<8 hex>" leaves 46 for the prefix
  bucket_prefix = (
    local.google_like ? "cs-${substr(sha1(var.prefix), 0, 8)}" :
    length(var.prefix) <= 46 ? lower(var.prefix) : replace(substr(lower(var.prefix), 0, 46), "/-+$/", "")
  )
}

resource "google_storage_bucket" "state" {
  project                     = var.project_id
  name                        = "${local.bucket_prefix}-tfstate-${random_id.suffix.hex}"
  location                    = var.location
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  labels                      = var.labels # already carries managedby=cloudseed

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      num_newer_versions = 20
      with_state         = "ARCHIVED"
    }
  }
}

output "bucket" { value = google_storage_bucket.state.name }
