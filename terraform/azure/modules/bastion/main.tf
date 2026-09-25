variable "prefix" { type = string }
variable "location" { type = string }
variable "resource_group_name" { type = string }
variable "subnet_id" { type = string }
variable "vm_size" { type = string }
variable "admin_username" { type = string }
variable "ssh_public_key" { type = string }
variable "tags" { type = map(string) }
variable "fips_mode" {
  type    = bool
  default = false
}

resource "azurerm_public_ip" "bastion" {
  name                = "${var.prefix}-bastion-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "bastion" {
  name                = "${var.prefix}-bastion-nic"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.bastion.id
  }
}

resource "azurerm_linux_virtual_machine" "bastion" {
  name                            = "${var.prefix}-bastion"
  location                        = var.location
  resource_group_name             = var.resource_group_name
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.bastion.id]
  secure_boot_enabled             = true
  vtpm_enabled                    = true
  # Role marks the VM's job; a user tag spelled role/ROLE would be the same tag to Azure (names are case-insensitive)
  tags = merge({ for k, v in var.tags : k => v if lower(k) != "role" }, { Role = "bastion" })

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  os_disk {
    name                 = "${var.prefix}-bastion-osdisk"
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

  custom_data = base64encode(<<-EOT
    #cloud-config
    package_update: true
    package_upgrade: true
    ssh_pwauth: false
    disable_root: true
  EOT
  )
}

output "public_ip" { value = azurerm_public_ip.bastion.ip_address }
output "private_ip" { value = azurerm_network_interface.bastion.private_ip_address }
output "vm_id" { value = azurerm_linux_virtual_machine.bastion.id }
# the VM's unique ID: unlike the resource ID (its name), it changes when the VM is re-created
output "instance_id" { value = azurerm_linux_virtual_machine.bastion.virtual_machine_id }
output "principal_id" { value = azurerm_linux_virtual_machine.bastion.identity[0].principal_id }
