# Private AKS cluster in the private subnet (Azure CNI overlay, NAT-gateway egress, workload identity).
variable "prefix" { type = string }
variable "location" { type = string }
variable "resource_group_name" { type = string }
variable "vnet_id" { type = string }
variable "subnet_id" { type = string }
variable "kubernetes_version" { type = string }
variable "node_vm_size" { type = string }
variable "node_count" { type = number }
variable "node_min" { type = number }
variable "node_max" { type = number }
variable "public_endpoint" { type = bool }
variable "authorized_ip_ranges" { type = list(string) }
variable "log_analytics_workspace_id" { type = string }
variable "tags" { type = map(string) }
variable "platform_prereqs" {
  description = "Cloud-side prerequisites for optional platform items (created on demand by `cs platform install`): velero."
  type        = list(string)
  default     = []
}
variable "fips_mode" {
  description = "FIPS 140 mode: FIPS-enabled node pool images."
  type        = bool
  default     = false
}
variable "private_nsg_name" {
  description = "NSG of the private (node) subnet: the pod CIDR and the bastion's ingress access are allowed on it."
  type        = string
}
variable "bastion_private_ip" {
  description = "Private IP of the bastion, allowed to reach internal ingress/gateway load balancers on 80/443."
  type        = string
}
variable "pod_cidr" {
  description = "Azure CNI Overlay pod address space (must not overlap the VNet or service_cidr)."
  type        = string
  default     = "10.244.0.0/16"
}

locals {
  name        = "${var.prefix}-aks"
  want_velero = contains(var.platform_prereqs, "velero")
  # The pool is created with this many nodes; afterwards the autoscaler owns the count (node_count is ignored below)
  # and `cloudseed node add/remove` moves min/max. Never below the minimum (the autoscaler would add those nodes anyway),
  # and a requested count above the maximum raises the maximum instead of being cut down to it: the create request
  # stays valid and the pool gets the size that was asked for (and that cost estimates use).
  initial_node_count = max(var.node_count, var.node_min)
  node_max           = max(var.node_max, local.initial_node_count)
}

# Azure CNI Overlay does not encapsulate pod-to-pod traffic, so the subnet NSG sees pod source addresses: without this
# rule the DenyAllInbound (4000) drops cross-node pod traffic, including DNS to CoreDNS on another node. Node->node and
# node->pod traffic is covered by AllowPrivateSubnetInternal (200); pod->outside traffic is SNATed to the node IP.
resource "azurerm_network_security_rule" "pods" {
  name                        = "AllowAKSPodCIDR"
  priority                    = 210
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = var.pod_cidr
  destination_address_prefix  = var.pod_cidr
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.private_nsg_name
}

# Ingress / gateway Services are internal load balancers in the private subnet (floating IP: the NSG sees the
# frontend address and the service port). Let the bastion reach them, so an SSH tunnel through it works like the VPN.
resource "azurerm_network_security_rule" "ingress_from_bastion" {
  name                        = "AllowIngressFromBastion"
  priority                    = 220
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["80", "443"]
  source_address_prefix       = var.bastion_private_ip
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.private_nsg_name
}

resource "azurerm_user_assigned_identity" "aks" {
  name                = "${local.name}-identity"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# The cluster identity must manage the pre-existing VNet/subnet (load balancers, routes).
resource "azurerm_role_assignment" "aks_network" {
  scope                = var.vnet_id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_user_assigned_identity.aks.principal_id
}

resource "azurerm_kubernetes_cluster" "this" {
  name                = local.name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = replace(local.name, "/[^a-zA-Z0-9-]/", "")
  kubernetes_version  = var.kubernetes_version
  sku_tier            = "Free"

  private_cluster_enabled = !var.public_endpoint
  # A private cluster's own API name (<prefix>.<id>.privatelink.<region>.azmk8s.io) resolves only inside the VNet: its
  # private DNS zone is linked to the VNet alone, so VPN / Tailscale clients could not resolve it. The public FQDN
  # (<prefix>-<id>.hcp.<region>.azmk8s.io) is a public DNS record holding the endpoint's private IP: the API server stays
  # unreachable from the Internet, but the name works over the VPN, through the bastion tunnel and inside the VNet
  # (the API server certificate covers it). An in-place update of an existing cluster.
  private_cluster_public_fqdn_enabled = !var.public_endpoint
  role_based_access_control_enabled   = true
  oidc_issuer_enabled                 = true
  workload_identity_enabled           = true
  azure_policy_enabled                = true

  default_node_pool {
    name = "system"
    # Changing vm_size, fips_enabled, os_disk_size_gb, ... rotates the pool through a temporary one; without a name
    # for it the provider refuses the update.
    temporary_name_for_rotation = "systemtmp"
    vm_size                     = var.node_vm_size
    vnet_subnet_id              = var.subnet_id
    auto_scaling_enabled        = true
    node_count                  = local.initial_node_count
    min_count                   = var.node_min
    max_count                   = local.node_max
    os_disk_size_gb             = 64
    os_sku                      = "AzureLinux"
    fips_enabled                = var.fips_mode
    upgrade_settings {
      max_surge = "33%"
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  network_profile {
    network_plugin      = "azure"
    network_plugin_mode = "overlay"
    network_policy      = "azure"
    outbound_type       = "userAssignedNATGateway"
    pod_cidr            = var.pod_cidr
    service_cidr        = "10.250.0.0/16"
    dns_service_ip      = "10.250.0.10"
  }

  dynamic "api_server_access_profile" {
    for_each = var.public_endpoint ? [1] : []
    content {
      authorized_ip_ranges = var.authorized_ip_ranges
    }
  }

  oms_agent {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  tags = var.tags

  lifecycle {
    ignore_changes = [default_node_pool[0].node_count]
  }

  # the NSG rules first: CoreDNS and the add-ons start while the cluster is created
  depends_on = [azurerm_role_assignment.aks_network, azurerm_network_security_rule.pods]
}

# Control-plane logs (API server, admin audit, controller manager, scheduler, autoscaler) into the environment's Log
# Analytics workspace, in the resource-specific AKSAudit* / AKSControlPlane tables. kube-audit-admin rather than
# kube-audit: the full audit log also records every get/list/watch and is very large.
resource "azurerm_monitor_diagnostic_setting" "control_plane" {
  name                           = "${local.name}-control-plane"
  target_resource_id             = azurerm_kubernetes_cluster.this.id
  log_analytics_workspace_id     = var.log_analytics_workspace_id
  log_analytics_destination_type = "Dedicated"

  dynamic "enabled_log" {
    for_each = toset(["kube-apiserver", "kube-audit-admin", "kube-controller-manager", "kube-scheduler", "cluster-autoscaler"])
    content {
      category = enabled_log.value
    }
  }
}

output "cluster_name" { value = azurerm_kubernetes_cluster.this.name }
# The API server name clients use: the public FQDN (a public cluster's, or the published name of a private one); the
# privatelink name (VNet only) only if a private cluster ever reports no public one.
output "endpoint" {
  value = try(coalesce(azurerm_kubernetes_cluster.this.fqdn, azurerm_kubernetes_cluster.this.private_fqdn), null)
}
output "oidc_issuer" { value = azurerm_kubernetes_cluster.this.oidc_issuer_url }

# ---- Workload identity for platform controllers (external-secrets reads Key Vault) ----
resource "azurerm_user_assigned_identity" "external_secrets" {
  name                = "${local.name}-external-secrets"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_federated_identity_credential" "external_secrets" {
  name                      = "external-secrets"
  user_assigned_identity_id = azurerm_user_assigned_identity.external_secrets.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject                   = "system:serviceaccount:external-secrets:external-secrets"
}

output "external_secrets_client_id" { value = azurerm_user_assigned_identity.external_secrets.client_id }
