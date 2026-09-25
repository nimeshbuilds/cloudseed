terraform {
  required_version = ">= 1.10"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # 4.65: azurerm_federated_identity_credential.user_assigned_identity_id (parent_id and resource_group_name are
      # deprecated and go away in 5.0)
      version = ">= 4.65, < 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
