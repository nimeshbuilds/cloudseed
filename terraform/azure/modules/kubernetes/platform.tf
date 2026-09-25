# Cloud-side prerequisites for platform items installed by `cs platform install` (workload identity + storage).

data "azurerm_client_config" "current" {}

# ---- external-dns: DNS zones in the environment's resource group ----
resource "azurerm_user_assigned_identity" "external_dns" {
  name                = "${local.name}-external-dns"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_federated_identity_credential" "external_dns" {
  name                      = "external-dns"
  user_assigned_identity_id = azurerm_user_assigned_identity.external_dns.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject                   = "system:serviceaccount:external-dns:external-dns"
}

resource "azurerm_role_assignment" "external_dns" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${var.resource_group_name}"
  role_definition_name = "DNS Zone Contributor"
  principal_id         = azurerm_user_assigned_identity.external_dns.principal_id
}

# ---- velero: hardened storage account + container, workload identity, least-privilege role for disk snapshots ----
resource "random_id" "velero" {
  count       = local.want_velero ? 1 : 0
  byte_length = 3
}

resource "azurerm_storage_account" "velero" {
  count = local.want_velero ? 1 : 0
  # Globally unique, at most 24 characters: the prefix is capped at 12 so the 6 random hex characters always survive
  # (12 + "velero" + 6 = 24); a truncated suffix made every long name/env pair (e.g. cloudseed-production) collide.
  name                            = "${substr(replace(lower(var.prefix), "/[^a-z0-9]/", ""), 0, 12)}velero${random_id.velero[0].hex}"
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  tags                            = var.tags

  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 14 }
    container_delete_retention_policy { days = 14 }
  }

  lifecycle {
    # an existing account keeps the name it was created with (renaming would replace it and delete the backups)
    ignore_changes = [name]
  }
}

resource "azurerm_storage_container" "velero" {
  count                 = local.want_velero ? 1 : 0
  name                  = "velero"
  storage_account_id    = azurerm_storage_account.velero[0].id
  container_access_type = "private"
}

resource "azurerm_user_assigned_identity" "velero" {
  count               = local.want_velero ? 1 : 0
  name                = "${local.name}-velero"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_federated_identity_credential" "velero" {
  count                     = local.want_velero ? 1 : 0
  name                      = "velero"
  user_assigned_identity_id = azurerm_user_assigned_identity.velero[0].id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject                   = "system:serviceaccount:velero:velero"
}

resource "azurerm_role_definition" "velero" {
  count = local.want_velero ? 1 : 0
  # Custom role names must be unique in the whole Entra tenant, not just the subscription: the subscription ID prefix
  # keeps same-named environments in different subscriptions of one tenant apart (a rename is an in-place update).
  name        = "${local.name}-velero-${substr(data.azurerm_client_config.current.subscription_id, 0, 8)}"
  scope       = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  description = "Velero: managed disk snapshots (cloudseed)"

  permissions {
    actions = [
      "Microsoft.Compute/disks/read", "Microsoft.Compute/disks/write", "Microsoft.Compute/disks/endGetAccess/action", "Microsoft.Compute/disks/beginGetAccess/action",
      "Microsoft.Compute/snapshots/read", "Microsoft.Compute/snapshots/write", "Microsoft.Compute/snapshots/delete",
      "Microsoft.Storage/storageAccounts/listkeys/action", "Microsoft.Storage/storageAccounts/regeneratekey/action", "Microsoft.Storage/storageAccounts/read",
    ]
  }
  assignable_scopes = [
    "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${var.resource_group_name}",
    "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${azurerm_kubernetes_cluster.this.node_resource_group}",
  ]
}

# for_each keys must be known when planning: the environment's resource group name is, the cluster's node resource group
# is not while the cluster is being created or replaced, so that assignment is a count-based resource of its own.
resource "azurerm_role_assignment" "velero_rg" {
  for_each           = local.want_velero ? toset([var.resource_group_name]) : toset([])
  scope              = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${each.value}"
  role_definition_id = azurerm_role_definition.velero[0].role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.velero[0].principal_id
}

resource "azurerm_role_assignment" "velero_node_rg" {
  count              = local.want_velero ? 1 : 0
  scope              = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${azurerm_kubernetes_cluster.this.node_resource_group}"
  role_definition_id = azurerm_role_definition.velero[0].role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.velero[0].principal_id
  # Environments created before this split hold the same assignment as velero_rg["MC_..."]. Azure refuses a second
  # identical assignment (RoleAssignmentExists), so that old instance must be deleted first: this ordering does it.
  depends_on = [azurerm_role_assignment.velero_rg]
}

resource "azurerm_role_assignment" "velero_blob" {
  count                = local.want_velero ? 1 : 0
  scope                = azurerm_storage_account.velero[0].id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.velero[0].principal_id
}

output "external_dns_client_id" { value = azurerm_user_assigned_identity.external_dns.client_id }
output "velero_client_id" { value = local.want_velero ? azurerm_user_assigned_identity.velero[0].client_id : null }
output "velero_storage_account" { value = local.want_velero ? azurerm_storage_account.velero[0].name : null }
output "velero_container" { value = local.want_velero ? azurerm_storage_container.velero[0].name : null }
output "node_resource_group" { value = azurerm_kubernetes_cluster.this.node_resource_group }
