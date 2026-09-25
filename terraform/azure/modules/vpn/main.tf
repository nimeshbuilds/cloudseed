# VPN host (OpenVPN or Tailscale subnet router) in the public subnet, configured by Ansible.
variable "prefix" { type = string }
variable "location" { type = string }
variable "resource_group_name" { type = string }
variable "subnet_id" { type = string }
variable "public_nsg_name" { type = string }
variable "private_nsg_name" { type = string }
variable "vpn_type" { type = string }
variable "vpn_port" { type = number }
variable "vm_size" { type = string }
variable "admin_username" { type = string }
variable "ssh_public_key" { type = string }
variable "tags" { type = map(string) }
variable "fips_mode" {
  type    = bool
  default = false
}

resource "azurerm_public_ip" "vpn" {
  name                = "${var.prefix}-vpn-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "vpn" {
  name                  = "${var.prefix}-vpn-nic"
  location              = var.location
  resource_group_name   = var.resource_group_name
  ip_forwarding_enabled = true
  tags                  = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vpn.id
  }
}

# Public NSG: open the VPN port to the world, only towards this VM.
resource "azurerm_network_security_rule" "vpn_port" {
  name                        = "AllowVPN"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = var.vpn_type == "openvpn" ? tostring(var.vpn_port) : "41641"
  source_address_prefix       = "Internet"
  destination_address_prefix  = azurerm_network_interface.vpn.private_ip_address
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.public_nsg_name
}

# Private NSG: VPN clients (NATed behind the VPN VM) may reach private workloads.
resource "azurerm_network_security_rule" "private_from_vpn" {
  name                        = "AllowFromVPN"
  priority                    = 150
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = azurerm_network_interface.vpn.private_ip_address
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.private_nsg_name
}

resource "azurerm_linux_virtual_machine" "vpn" {
  name                            = "${var.prefix}-vpn"
  location                        = var.location
  resource_group_name             = var.resource_group_name
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.vpn.id]
  secure_boot_enabled             = true
  vtpm_enabled                    = true
  # Role marks the VM's job; a user tag spelled role/ROLE would be the same tag to Azure (names are case-insensitive)
  tags = merge({ for k, v in var.tags : k => v if lower(k) != "role" }, { Role = "vpn" })

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  os_disk {
    name                 = "${var.prefix}-vpn-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  # Ubuntu Pro FIPS (marketplace plan, terms accepted by the root module) in FIPS mode; plain Ubuntu LTS otherwise.
  source_image_reference {
    publisher = "Canonical"
    offer     = var.fips_mode ? "0001-com-ubuntu-pro-jammy-fips" : "ubuntu-24_04-lts"
    sku       = var.fips_mode ? "pro-fips-22_04-gen2" : "server"
    version   = "latest"
  }

  dynamic "plan" {
    for_each = var.fips_mode ? [1] : []
    content {
      name      = "pro-fips-22_04-gen2"
      product   = "0001-com-ubuntu-pro-jammy-fips"
      publisher = "canonical"
    }
  }

  identity {
    type = "SystemAssigned"
  }
}

output "public_ip" { value = azurerm_public_ip.vpn.ip_address }
output "vm_id" { value = azurerm_linux_virtual_machine.vpn.id }
# the VM's unique ID: unlike the resource ID (its name), it changes when the VM is re-created
output "instance_id" { value = azurerm_linux_virtual_machine.vpn.virtual_machine_id }
