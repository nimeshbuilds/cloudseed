# Hardened storage account + container for Terraform remote state.

terraform {
  required_version = ">= 1.10"
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # 4.9: azurerm_storage_container.storage_account_id (below). The root cloudseed renders asks for the same range
      # (Azure.AZURERM_BOOTSTRAP_VERSION), below the stack's 4.65, so a state root locked to 4.9+ is never forced to
      # upgrade just to be destroyed.
      version = ">= 4.9, < 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "location" { type = string }
variable "prefix" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}

resource "random_string" "suffix" {
  length  = 8
  lower   = true
  upper   = false
  numeric = true
  special = false
}

locals {
  tags         = merge(var.tags, { ManagedBy = "cloudseed" })
  account_name = "${substr(replace(lower(var.prefix), "/[^a-z0-9]/", ""), 0, 14)}ts${random_string.suffix.result}"
}

resource "azurerm_resource_group" "state" {
  name     = "${var.prefix}-tfstate-rg"
  location = var.location
  tags     = local.tags
}

resource "azurerm_storage_account" "state" {
  name                            = local.account_name
  resource_group_name             = azurerm_resource_group.state.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  tags                            = local.tags

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
}

resource "azurerm_storage_container" "state" {
  name                  = "tfstate"
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

output "resource_group_name" { value = azurerm_resource_group.state.name }
output "storage_account_name" { value = azurerm_storage_account.state.name }
output "container_name" { value = azurerm_storage_container.state.name }
