variable "prefix" { type = string }
variable "location" { type = string }
variable "resource_group_name" { type = string }
variable "vnet_cidr" { type = string }
variable "public_subnet_cidr" { type = string }
variable "private_subnet_cidr" { type = string }
variable "allowed_ssh_cidrs" { type = list(string) }
variable "tags" { type = map(string) }

resource "azurerm_virtual_network" "this" {
  name                = "${var.prefix}-vnet"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = [var.vnet_cidr]
  tags                = var.tags
}

resource "azurerm_subnet" "public" {
  name                            = "${var.prefix}-public"
  resource_group_name             = var.resource_group_name
  virtual_network_name            = azurerm_virtual_network.this.name
  address_prefixes                = [var.public_subnet_cidr]
  default_outbound_access_enabled = false
}

resource "azurerm_subnet" "private" {
  name                            = "${var.prefix}-private"
  resource_group_name             = var.resource_group_name
  virtual_network_name            = azurerm_virtual_network.this.name
  address_prefixes                = [var.private_subnet_cidr]
  default_outbound_access_enabled = false
}

# ---- NSG: public / bastion subnet ----
resource "azurerm_network_security_group" "public" {
  name                = "${var.prefix}-public-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "public_allow_ssh" {
  name                        = "AllowSSHFromAllowedSources"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefixes     = var.allowed_ssh_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.public.name
}

resource "azurerm_network_security_rule" "public_deny_all" {
  name                        = "DenyAllInbound"
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.public.name
}

resource "azurerm_subnet_network_security_group_association" "public" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.public.id
}

# ---- NSG: private / workload subnet ----
resource "azurerm_network_security_group" "private" {
  name                = "${var.prefix}-private-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "private_allow_ssh_from_bastion" {
  name                        = "AllowSSHFromBastionSubnet"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.public_subnet_cidr
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.private.name
}

resource "azurerm_network_security_rule" "private_allow_internal" {
  name                        = "AllowPrivateSubnetInternal"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = var.private_subnet_cidr
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.private.name
}

# The deny-all below also shadows Azure's default AllowAzureLoadBalancerInBound (65001): restore it explicitly, or the
# health probes (always from 168.63.129.16, the AzureLoadBalancer tag) of internal load balancers in this subnet fail
# and every backend is marked down (AKS ingress / gateway Services are internal load balancers here). Probe ports are
# dynamic (NodePorts, healthCheckNodePort, kube-proxy 10256), so all ports.
resource "azurerm_network_security_rule" "private_allow_azure_lb" {
  name                        = "AllowAzureLoadBalancerInBound"
  priority                    = 300
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "AzureLoadBalancer"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.private.name
}

resource "azurerm_network_security_rule" "private_deny_all" {
  name                        = "DenyAllInbound"
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.private.name
}

resource "azurerm_subnet_network_security_group_association" "private" {
  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = azurerm_network_security_group.private.id
}

# ---- NAT gateway for private egress ----
resource "azurerm_public_ip" "nat" {
  name                = "${var.prefix}-nat-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_nat_gateway" "this" {
  name                    = "${var.prefix}-nat"
  location                = var.location
  resource_group_name     = var.resource_group_name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 10
  tags                    = var.tags
}

resource "azurerm_nat_gateway_public_ip_association" "this" {
  nat_gateway_id       = azurerm_nat_gateway.this.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "private" {
  subnet_id      = azurerm_subnet.private.id
  nat_gateway_id = azurerm_nat_gateway.this.id
}

output "vnet_id" { value = azurerm_virtual_network.this.id }
output "public_subnet_id" { value = azurerm_subnet.public.id }
# Consumers (the AKS node pool with outbound_type = userAssignedNATGateway) need the subnet with its NAT gateway and NSG
# attached, not just the subnet: an output is evaluated on its own, so the dependency is explicit.
output "private_subnet_id" {
  value = azurerm_subnet.private.id
  depends_on = [
    azurerm_subnet_nat_gateway_association.private,
    azurerm_subnet_network_security_group_association.private,
    azurerm_nat_gateway_public_ip_association.this,
  ]
}
output "nat_public_ip" { value = azurerm_public_ip.nat.ip_address }
output "public_nsg_name" { value = azurerm_network_security_group.public.name }
output "private_nsg_name" { value = azurerm_network_security_group.private.name }
