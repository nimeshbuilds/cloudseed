# cloudseed Azure stack: VNet + NSGs + NAT + bastion VM + logging baseline.

locals {
  prefix = "${var.name}-${var.environment}"
  # Environment first, so a --tag Environment=... (cloudseed folds any spelling onto that key) wins on every resource,
  # as it does in the summary; ManagedBy last: it marks what cloudseed created
  tags = merge({ Environment = var.environment }, var.tags, { ManagedBy = "cloudseed" })
  # Who may reach a public AKS API server (kubernetes_public_endpoint = true): your allowed CIDRs, plus the NAT gateway
  # egress IP the nodes use to reach it (kubelet, konnectivity, node bootstrap; AKS does not add it by itself for
  # outbound_type = userAssignedNATGateway) and the bastion (kubectl there, and the SSH-tunnel fallback).
  kubernetes_authorized_ranges = distinct(concat(var.allowed_ssh_cidrs, [
    "${module.network.nat_public_ip}/32",
    "${module.bastion.public_ip}/32",
  ]))
}

# The credentials Terraform runs with (tenant and subscription outputs, with or without AKS).
data "azurerm_client_config" "current" {}

# Ubuntu Pro FIPS is a marketplace image: its terms must be accepted once per subscription.
resource "azurerm_marketplace_agreement" "ubuntu_pro_fips" {
  count     = var.fips_mode ? 1 : 0
  publisher = "canonical"
  offer     = "0001-com-ubuntu-pro-jammy-fips"
  plan      = "pro-fips-22_04-gen2"
}

resource "azurerm_resource_group" "this" {
  name     = "${local.prefix}-rg"
  location = var.location
  tags     = local.tags
}

module "network" {
  source = "./modules/network"

  prefix              = local.prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  vnet_cidr           = var.network_cidr
  public_subnet_cidr  = cidrsubnet(var.network_cidr, var.subnet_newbits, 0)
  private_subnet_cidr = cidrsubnet(var.network_cidr, var.subnet_newbits, 1)
  allowed_ssh_cidrs   = var.allowed_ssh_cidrs
  tags                = local.tags
}

module "bastion" {
  source = "./modules/bastion"

  prefix              = local.prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = module.network.public_subnet_id
  vm_size             = var.bastion_vm_size
  admin_username      = var.admin_username
  ssh_public_key      = var.ssh_public_key
  tags                = local.tags
  fips_mode           = var.fips_mode

  # the Ubuntu Pro FIPS image can only be deployed once its marketplace terms are accepted
  depends_on = [azurerm_marketplace_agreement.ubuntu_pro_fips]
}

module "security_baseline" {
  source = "./modules/security-baseline"

  prefix              = local.prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  enable_activity_log = var.enable_activity_log
  log_retention_days  = var.log_retention_days
  enable_defender     = var.enable_defender
  tags                = local.tags
}

module "kubernetes" {
  count  = var.enable_kubernetes ? 1 : 0
  source = "./modules/kubernetes"

  prefix                     = local.prefix
  location                   = var.location
  resource_group_name        = azurerm_resource_group.this.name
  vnet_id                    = module.network.vnet_id
  subnet_id                  = module.network.private_subnet_id
  kubernetes_version         = var.kubernetes_version
  node_vm_size               = var.kubernetes_node_size
  node_count                 = var.kubernetes_node_count
  node_min                   = var.kubernetes_node_min
  node_max                   = var.kubernetes_node_max
  public_endpoint            = var.kubernetes_public_endpoint
  authorized_ip_ranges       = local.kubernetes_authorized_ranges
  log_analytics_workspace_id = module.security_baseline.log_analytics_workspace_id
  platform_prereqs           = var.platform_prereqs
  fips_mode                  = var.fips_mode
  private_nsg_name           = module.network.private_nsg_name
  bastion_private_ip         = module.bastion.private_ip
  tags                       = local.tags
}

module "vpn" {
  count  = var.enable_vpn ? 1 : 0
  source = "./modules/vpn"

  prefix              = local.prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = module.network.public_subnet_id
  public_nsg_name     = module.network.public_nsg_name
  private_nsg_name    = module.network.private_nsg_name
  vpn_type            = var.vpn_type
  vpn_port            = var.vpn_port
  vm_size             = var.vpn_vm_size
  admin_username      = var.admin_username
  ssh_public_key      = var.ssh_public_key
  tags                = local.tags
  fips_mode           = var.fips_mode

  depends_on = [azurerm_marketplace_agreement.ubuntu_pro_fips]
}
