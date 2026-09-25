# Plan/apply-level checks of the Azure stack with mock providers (no credentials, no cloud calls).
# Run: CLOUDSEED_TF_TESTS=1 python3 -m unittest tests.test_fix_azure
#  or: terraform -chdir=terraform/azure init -backend=false && terraform -chdir=terraform/azure test

# The provider still validates the (mocked) IDs it receives, so every ID another resource consumes is well formed.
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      subscription_id = "0123abcd-0000-0000-0000-000000000000"
      tenant_id       = "00000000-0000-0000-0000-00000000beef"
    }
  }
  mock_resource "azurerm_resource_group" {
    defaults = { id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg" }
  }
  mock_resource "azurerm_virtual_network" {
    defaults = { id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/virtualNetworks/vnet" }
  }
  mock_resource "azurerm_subnet" {
    defaults = { id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet" }
  }
  mock_resource "azurerm_network_security_group" {
    defaults = { id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/networkSecurityGroups/nsg" }
  }
  mock_resource "azurerm_public_ip" {
    defaults = {
      id         = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/publicIPAddresses/pip"
      ip_address = "20.30.40.50"
    }
  }
  mock_resource "azurerm_nat_gateway" {
    defaults = { id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/natGateways/nat" }
  }
  mock_resource "azurerm_network_interface" {
    defaults = {
      id                 = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/networkInterfaces/nic"
      private_ip_address = "10.20.0.4"
    }
  }
  mock_resource "azurerm_linux_virtual_machine" {
    defaults = { id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Compute/virtualMachines/vm" }
  }
  mock_resource "azurerm_log_analytics_workspace" {
    defaults = { id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.OperationalInsights/workspaces/logs" }
  }
  mock_resource "azurerm_user_assigned_identity" {
    defaults = {
      id           = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai"
      principal_id = "11111111-1111-1111-1111-111111111111"
      client_id    = "22222222-2222-2222-2222-222222222222"
    }
  }
  mock_resource "azurerm_kubernetes_cluster" {
    defaults = {
      id                  = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.ContainerService/managedClusters/aks"
      oidc_issuer_url     = "https://eastus.oic.prod-aks.azure.com/00000000-0000-0000-0000-00000000beef/aks/"
      node_resource_group = "MC_cloudseed-dev-rg_cloudseed-dev-aks_eastus"
    }
  }
  mock_resource "azurerm_role_definition" {
    defaults = { role_definition_resource_id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/33333333-3333-3333-3333-333333333333" }
  }
  mock_resource "azurerm_storage_account" {
    defaults = { id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Storage/storageAccounts/sa" }
  }
}

mock_provider "random" {
  mock_resource "random_id" {
    defaults = { hex = "a1b2c3" }
  }
}

variables {
  location          = "eastus"
  name              = "cloudseed"
  environment       = "dev"
  allowed_ssh_cidrs = ["203.0.113.7/32"]
  ssh_public_key    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC test"
}

# A fresh environment (or one whose cluster is being re-created) with the velero prerequisites recorded must plan:
# the node resource group is unknown until the cluster exists, so it cannot key a for_each.
run "fresh_plan_with_velero" {
  command = plan
  variables {
    enable_kubernetes = true
    enable_vpn        = true
    platform_prereqs  = ["velero"]
  }
}

# tenant_id / subscription_id come from the credentials Terraform runs with, so they are set without AKS too.
run "identity_outputs_without_kubernetes" {
  command = plan
  assert {
    condition     = output.tenant_id == "00000000-0000-0000-0000-00000000beef" && output.subscription_id == "0123abcd-0000-0000-0000-000000000000"
    error_message = "tenant_id and subscription_id must not be null when Kubernetes is off"
  }
  assert {
    condition     = output.vpn_port == null && output.vpn_type == null
    error_message = "no VPN, no port"
  }
}

run "tailscale_reports_its_port" {
  command = plan
  variables {
    enable_vpn = true
    vpn_type   = "tailscale"
  }
  assert {
    condition     = output.vpn_port == 41641
    error_message = "a Tailscale VPN host listens on 41641 (what the NSG opens), not the OpenVPN port"
  }
}

run "openvpn_reports_vpn_port" {
  command = plan
  variables {
    enable_vpn = true
    vpn_port   = 1195
  }
  assert {
    condition     = output.vpn_port == 1195
    error_message = "an OpenVPN host reports vpn_port"
  }
}

run "vpn_port_zero_is_refused" {
  command = plan
  variables {
    enable_vpn = true
    vpn_port   = 0
  }
  expect_failures = [var.vpn_port]
}

run "vpn_port_above_65535_is_refused" {
  command = plan
  variables {
    enable_vpn = true
    vpn_port   = 70000
  }
  expect_failures = [var.vpn_port]
}

run "fractional_vpn_port_is_refused" {
  command = plan
  variables {
    enable_vpn = true
    vpn_port   = 1194.5
  }
  expect_failures = [var.vpn_port]
}

# The VMs' unique IDs (vmId) are outputs: provision.forget_replaced_hosts drops the remembered SSH host key of a host
# whose ID changed (a re-created VM behind the same static public IP has new host keys).
run "host_instance_ids" {
  variables {
    enable_vpn = true
  }
  assert {
    condition     = output.bastion_instance_id != null && output.bastion_instance_id != "" && output.vpn_instance_id != null && output.vpn_instance_id != ""
    error_message = "bastion_instance_id and vpn_instance_id must report the VMs' vmId"
  }
}

run "no_vpn_no_vpn_instance_id" {
  variables {
    enable_vpn = false
  }
  assert {
    condition     = output.vpn_instance_id == null && output.bastion_instance_id != null
    error_message = "without a VPN host there is no vpn_instance_id"
  }
}

# A --tag Environment=... (folded onto that key by cloudseed) reaches every resource; ManagedBy stays cloudseed's.
run "environment_tag_override_wins" {
  command = plan
  variables {
    tags = { Environment = "staging", team = "a" }
  }
  assert {
    condition     = local.tags["Environment"] == "staging" && local.tags["ManagedBy"] == "cloudseed" && local.tags["team"] == "a"
    error_message = "the user's Environment tag must win over the env name; ManagedBy stays cloudseed"
  }
  assert {
    condition     = azurerm_resource_group.this.tags["Environment"] == "staging"
    error_message = "resources carry the overridden Environment tag"
  }
}

run "environment_tag_defaults_to_the_env" {
  command = plan
  assert {
    condition     = local.tags["Environment"] == "dev" && local.tags["ManagedBy"] == "cloudseed"
    error_message = "without an override the Environment tag is the environment name"
  }
}

# Tag names are case-insensitive on Azure: a user's role tag must not sit next to cloudseed's Role on the VMs.
run "vm_role_tag_is_not_duplicated" {
  command = plan
  module {
    source = "./modules/bastion"
  }
  variables {
    prefix              = "cloudseed-dev"
    location            = "eastus"
    resource_group_name = "cloudseed-dev-rg"
    subnet_id           = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/virtualNetworks/v/subnets/public"
    vm_size             = "Standard_B1s"
    admin_username      = "azureuser"
    ssh_public_key      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC test"
    tags                = { role = "frontend", team = "a" }
  }
  assert {
    condition     = azurerm_linux_virtual_machine.bastion.tags == tomap({ Role = "bastion", team = "a" })
    error_message = "the VM keeps one Role tag (cloudseed's) and the user's other tags"
  }
}

run "reserved_admin_username_is_refused" {
  command = plan
  variables {
    admin_username = "Admin"
  }
  expect_failures = [var.admin_username]
}

run "log_retention_above_the_maximum_is_refused" {
  command = plan
  variables {
    log_retention_days = 1000
  }
  expect_failures = [var.log_retention_days]
}

run "log_retention_below_30_is_raised" {
  command = plan
  variables {
    log_retention_days = 7
  }
}

run "fips_plan" {
  command = plan
  variables {
    fips_mode         = true
    enable_kubernetes = true
    enable_vpn        = true
  }
}

run "public_endpoint_authorizes_nat_and_bastion" {
  variables {
    enable_kubernetes          = true
    kubernetes_public_endpoint = true
  }
  assert {
    condition     = contains(local.kubernetes_authorized_ranges, "203.0.113.7/32")
    error_message = "the user's CIDR must stay authorized"
  }
  assert {
    condition     = contains(local.kubernetes_authorized_ranges, "20.30.40.50/32")
    error_message = "the NAT egress IP (and the bastion) must be authorized on a public API server"
  }
  assert {
    condition     = length(local.kubernetes_authorized_ranges) == length(distinct(local.kubernetes_authorized_ranges))
    error_message = "authorized ranges must not repeat"
  }
}

run "node_max_below_min_is_refused" {
  command = plan
  variables {
    enable_kubernetes   = true
    kubernetes_node_min = 3
    kubernetes_node_max = 2
  }
  expect_failures = [var.kubernetes_node_max]
}

run "node_min_zero_is_refused" {
  command = plan
  variables {
    enable_kubernetes   = true
    kubernetes_node_min = 0
  }
  expect_failures = [var.kubernetes_node_min]
}

# ---- network module ----
run "private_nsg_allows_load_balancer_probes" {
  module {
    source = "./modules/network"
  }
  variables {
    prefix              = "cloudseed-dev"
    resource_group_name = "cloudseed-dev-rg"
    vnet_cidr           = "10.20.0.0/16"
    public_subnet_cidr  = "10.20.0.0/24"
    private_subnet_cidr = "10.20.1.0/24"
    tags                = {}
  }
  assert {
    condition     = azurerm_network_security_rule.private_allow_azure_lb.source_address_prefix == "AzureLoadBalancer"
    error_message = "health probes of internal load balancers come from the AzureLoadBalancer tag"
  }
  assert {
    condition     = azurerm_network_security_rule.private_allow_azure_lb.priority < azurerm_network_security_rule.private_deny_all.priority
    error_message = "the probe rule must be evaluated before DenyAllInbound"
  }
  assert {
    condition     = azurerm_network_security_rule.private_allow_azure_lb.network_security_group_name == azurerm_network_security_group.private.name
    error_message = "the probe rule belongs on the private NSG"
  }
}

# ---- security baseline module ----
# Defender plans name their sub-plan: the provider forces a replacement (Defender off, then on, for the whole
# subscription) when the sub-plan the API reports differs from the configuration.
run "defender_plans_name_their_subplan" {
  command = plan
  module {
    source = "./modules/security-baseline"
  }
  variables {
    prefix              = "cloudseed-dev"
    location            = "eastus"
    resource_group_name = "cloudseed-dev-rg"
    enable_activity_log = true
    log_retention_days  = 30
    enable_defender     = true
    tags                = {}
  }
  assert {
    condition     = azurerm_security_center_subscription_pricing.this["VirtualMachines"].subplan == "P2"
    error_message = "Defender for Servers must name its sub-plan (P2, what a Standard tier without one gets)"
  }
  assert {
    condition     = azurerm_security_center_subscription_pricing.this["StorageAccounts"].subplan == "DefenderForStorageV2"
    error_message = "Defender for Storage must name its sub-plan (DefenderForStorageV2)"
  }
  assert {
    condition     = length(azurerm_security_center_subscription_pricing.this) == 2 && alltrue([for p in azurerm_security_center_subscription_pricing.this : p.tier == "Standard" && p.resource_type != ""])
    error_message = "both plans are Standard and keyed by their resource type"
  }
}

run "defender_off_creates_no_pricing" {
  command = plan
  module {
    source = "./modules/security-baseline"
  }
  variables {
    prefix              = "cloudseed-dev"
    location            = "eastus"
    resource_group_name = "cloudseed-dev-rg"
    enable_activity_log = false
    log_retention_days  = 30
    enable_defender     = false
    tags                = {}
  }
  assert {
    condition     = length(azurerm_security_center_subscription_pricing.this) == 0
    error_message = "Defender is opt-in"
  }
}

# ---- kubernetes module ----
run "aks_module" {
  module {
    source = "./modules/kubernetes"
  }
  variables {
    prefix                     = "cloudseed-production"
    resource_group_name        = "cloudseed-production-rg"
    vnet_id                    = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-production-rg/providers/Microsoft.Network/virtualNetworks/v"
    subnet_id                  = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-production-rg/providers/Microsoft.Network/virtualNetworks/v/subnets/private"
    kubernetes_version         = null
    node_vm_size               = "Standard_B2s"
    node_count                 = 2
    node_min                   = 3
    node_max                   = 5
    public_endpoint            = false
    authorized_ip_ranges       = []
    log_analytics_workspace_id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-production-rg/providers/Microsoft.OperationalInsights/workspaces/logs"
    platform_prereqs           = ["velero"]
    private_nsg_name           = "cloudseed-production-private-nsg"
    bastion_private_ip         = "10.20.0.4"
    tags                       = {}
  }

  # pod-to-pod (incl. DNS) traffic keeps pod source addresses under CNI Overlay
  assert {
    condition     = azurerm_network_security_rule.pods.source_address_prefix == azurerm_kubernetes_cluster.this.network_profile[0].pod_cidr
    error_message = "the NSG must allow the cluster's pod CIDR"
  }
  assert {
    condition     = azurerm_network_security_rule.pods.network_security_group_name == "cloudseed-production-private-nsg" && azurerm_network_security_rule.pods.priority < 4000
    error_message = "the pod rule belongs on the private NSG, before DenyAllInbound"
  }
  assert {
    condition     = azurerm_network_security_rule.ingress_from_bastion.source_address_prefix == "10.20.0.4" && toset(azurerm_network_security_rule.ingress_from_bastion.destination_port_ranges) == toset(["80", "443"])
    error_message = "the bastion must reach internal ingress load balancers on 80/443"
  }
  # resizing / FIPS changes rotate the pool
  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].temporary_name_for_rotation == "systemtmp"
    error_message = "temporary_name_for_rotation is required to change vm_size, fips_enabled, ..."
  }
  # the pool never starts below its autoscaler minimum
  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].node_count == 3
    error_message = "node_count must be clamped into [min, max]"
  }
  # a private cluster publishes a public DNS name of its private endpoint (the privatelink name resolves inside the
  # VNet only, so VPN clients could not reach the API) and reports that name
  assert {
    condition     = azurerm_kubernetes_cluster.this.private_cluster_enabled && azurerm_kubernetes_cluster.this.private_cluster_public_fqdn_enabled
    error_message = "a private cluster must publish its public FQDN, or the API is unreachable over the VPN"
  }
  assert {
    condition     = output.endpoint == azurerm_kubernetes_cluster.this.fqdn
    error_message = "the endpoint of a private cluster is its public FQDN, not the VNet-only privatelink name"
  }
  # control-plane logs
  assert {
    condition     = contains([for l in azurerm_monitor_diagnostic_setting.control_plane.enabled_log : l.category], "kube-audit-admin") && contains([for l in azurerm_monitor_diagnostic_setting.control_plane.enabled_log : l.category], "kube-apiserver")
    error_message = "kube-audit-admin and kube-apiserver logs must go to Log Analytics"
  }
  # globally unique storage account name: the random part survives a long name/env
  assert {
    condition     = azurerm_storage_account.velero[0].name == "cloudseedprovelero${random_id.velero[0].hex}" && length(azurerm_storage_account.velero[0].name) <= 24
    error_message = "the velero storage account name must keep its random suffix and fit 24 characters"
  }
  # tenant-unique custom role name
  assert {
    condition     = azurerm_role_definition.velero[0].name == "cloudseed-production-aks-velero-0123abcd"
    error_message = "the velero role name must include the subscription"
  }
  assert {
    condition     = length(azurerm_role_assignment.velero_rg) == 1 && length(azurerm_role_assignment.velero_node_rg) == 1
    error_message = "velero needs its role on the environment and the node resource groups"
  }
  assert {
    condition     = azurerm_federated_identity_credential.velero[0].user_assigned_identity_id == azurerm_user_assigned_identity.velero[0].id
    error_message = "federated credentials use user_assigned_identity_id (parent_id is deprecated)"
  }
}

run "aks_module_count_above_max" {
  command   = plan
  state_key = "aks_new_cluster" # a cluster of its own (the one above already exists: its node_count is ignored)
  module {
    source = "./modules/kubernetes"
  }
  variables {
    prefix                     = "cloudseed-dev"
    resource_group_name        = "cloudseed-dev-rg"
    vnet_id                    = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/virtualNetworks/v"
    subnet_id                  = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.Network/virtualNetworks/v/subnets/private"
    kubernetes_version         = null
    node_vm_size               = "Standard_B2s"
    node_count                 = 9
    node_min                   = 1
    node_max                   = 4
    public_endpoint            = true
    authorized_ip_ranges       = ["203.0.113.7/32"]
    log_analytics_workspace_id = "/subscriptions/0123abcd-0000-0000-0000-000000000000/resourceGroups/cloudseed-dev-rg/providers/Microsoft.OperationalInsights/workspaces/logs"
    platform_prereqs           = []
    private_nsg_name           = "cloudseed-dev-private-nsg"
    bastion_private_ip         = "10.20.0.4"
    tags                       = {}
  }
  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].node_count == 9 && azurerm_kubernetes_cluster.this.default_node_pool[0].max_count == 9
    error_message = "a requested node_count above the maximum is honoured by raising the maximum (never silently cut down)"
  }
  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].min_count == 1
    error_message = "the autoscaler minimum stays as configured"
  }
  assert {
    condition     = !azurerm_kubernetes_cluster.this.private_cluster_enabled && !azurerm_kubernetes_cluster.this.private_cluster_public_fqdn_enabled
    error_message = "a public cluster has no private endpoint to publish"
  }
  assert {
    condition     = length(azurerm_storage_account.velero) == 0 && length(azurerm_role_assignment.velero_node_rg) == 0
    error_message = "velero prerequisites only exist when requested"
  }
}
