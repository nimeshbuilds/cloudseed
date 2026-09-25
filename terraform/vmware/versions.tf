terraform {
  required_version = ">= 1.10"

  required_providers {
    vmdesktop = {
      source  = "registry.local/cloudseed/vmdesktop"
      version = "~> 0.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
