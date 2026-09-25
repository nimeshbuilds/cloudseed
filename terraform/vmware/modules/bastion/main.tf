variable "prefix" { type = string }
variable "vm_dir" { type = string }
variable "base_disk" { type = string }
variable "guest_os_id" { type = string }
variable "private_cidr" { type = string }
variable "private_ip" { type = string }
variable "prefix_len" { type = number }
variable "cpus" { type = number }
variable "memory_mb" { type = number }
variable "disk_gb" { type = number }
variable "ssh_public_key" { type = string }
variable "ssh_username" { type = string }
variable "packages" { type = list(string) }
variable "legacy_user_data" {
  description = "Recorded user-data of existing VMs created from the previous first-boot template, by VM name (set by cloudseed)."
  type        = map(string)
  default     = {}
}

terraform {
  required_providers {
    vmdesktop = { source = "registry.local/cloudseed/vmdesktop" }
    random    = { source = "hashicorp/random" }
  }
}

# dhcp is deliberately not set: VMware cannot change it after the fact and the built-in host-only vmnet (adopted by
# default) has it on. Guests use static addresses below the DHCP pool, so either value works.
resource "vmdesktop_network" "private" {
  type   = "hostonly"
  subnet = var.private_cidr
}

# Static MACs so cloud-init can match interfaces by MAC (names differ between amd64 and arm64 guests).
resource "random_integer" "mac" {
  count = 6
  min   = 0
  max   = 255
}

locals {
  mac_nat  = format("00:50:56:%02x:%02x:%02x", random_integer.mac[0].result % 64, random_integer.mac[1].result, random_integer.mac[2].result)
  mac_priv = format("00:50:56:%02x:%02x:%02x", random_integer.mac[3].result % 64, random_integer.mac[4].result, random_integer.mac[5].result)

  network_config = yamlencode({
    version = 2
    ethernets = {
      nat = {
        match    = { macaddress = local.mac_nat }
        set-name = "eth0"
        dhcp4    = true
      }
      priv = {
        match     = { macaddress = local.mac_priv }
        set-name  = "eth1"
        addresses = ["${var.private_ip}/${var.prefix_len}"]
      }
    }
  })

  # The SSH key as a plain YAML scalar where that is safe, else quoted (JSON strings are valid YAML): a key comment with
  # ': ' or ending in ':' would be read as a mapping and no key installed. (Used by the frozen template below.)
  ssh_key_head = split(" #", var.ssh_public_key)[0]
  ssh_key_yaml = (length(regexall(":([[:space:]]|$)", local.ssh_key_head)) > 0 || length(regexall("[[:cntrl:]]", var.ssh_public_key)) > 0
  ? jsonencode(var.ssh_public_key) : var.ssh_public_key)

  # The apt timers are switched off for the first boot only (cloud-init-per instance): package installation must not
  # race apt-daily for the dpkg lock, and the hardening role then enables them for the automatic security updates. The
  # SSH key is a JSON string (valid YAML), so any key comment works - one with ': ' would otherwise be read as a mapping.
  user_data = <<-EOT
    #cloud-config
    bootcmd:
      - [cloud-init-per, instance, cloudseed-apt-off, sh, -c, "systemctl disable --now apt-daily.timer apt-daily-upgrade.timer; systemctl mask apt-daily.service apt-daily-upgrade.service"]
    hostname: ${var.prefix}-bastion
    manage_etc_hosts: true
    users:
      - name: ${var.ssh_username}
        groups: [sudo]
        sudo: ["ALL=(ALL) NOPASSWD:ALL"]
        shell: /bin/bash
        lock_passwd: true
        ssh_authorized_keys:
          - ${jsonencode(var.ssh_public_key)}
    ssh_pwauth: false
    disable_root: true
    package_update: true
    packages: ${jsonencode(concat(["open-vm-tools", "nftables"], var.packages))}
    write_files:
      - path: /etc/sysctl.d/90-cloudseed-forward.conf
        content: |
          net.ipv4.ip_forward = 1
      - path: /etc/nftables.conf
        permissions: "0600"
        content: |
          #!/usr/sbin/nft -f
          flush ruleset
          table inet filter {
            chain input { type filter hook input priority 0; policy accept; }
            chain forward {
              type filter hook forward priority 0; policy drop;
              ct state established,related accept
              ip saddr ${var.private_cidr} accept
            }
          }
          table ip nat {
            chain postrouting {
              type nat hook postrouting priority 100; policy accept;
              ip saddr ${var.private_cidr} oifname "eth0" masquerade
            }
          }
    runcmd:
      - sysctl --system
      - systemctl enable --now nftables
      - nft -f /etc/nftables.conf
  EOT

  # FROZEN - the previous template, byte for byte, which masked the apt timers on every boot. Any change to a VM's
  # cloud-init rebuilds it, so a bastion created from this template keeps it (see user_data_final); do not edit.
  # Its key is quoted only where the plain form was broken anyway (a comment with ': ', or ending in ':').
  user_data_legacy = <<-EOT
    #cloud-config
    bootcmd:
      - [systemctl, disable, --now, apt-daily.timer, apt-daily-upgrade.timer]
      - [systemctl, mask, apt-daily.service, apt-daily-upgrade.service]
    hostname: ${var.prefix}-bastion
    manage_etc_hosts: true
    users:
      - name: ${var.ssh_username}
        groups: [sudo]
        sudo: ["ALL=(ALL) NOPASSWD:ALL"]
        shell: /bin/bash
        lock_passwd: true
        ssh_authorized_keys:
          - ${local.ssh_key_yaml}
    ssh_pwauth: false
    disable_root: true
    package_update: true
    packages: ${jsonencode(concat(["open-vm-tools", "nftables"], var.packages))}
    write_files:
      - path: /etc/sysctl.d/90-cloudseed-forward.conf
        content: |
          net.ipv4.ip_forward = 1
      - path: /etc/nftables.conf
        permissions: "0600"
        content: |
          #!/usr/sbin/nft -f
          flush ruleset
          table inet filter {
            chain input { type filter hook input priority 0; policy accept; }
            chain forward {
              type filter hook forward priority 0; policy drop;
              ct state established,related accept
              ip saddr ${var.private_cidr} accept
            }
          }
          table ip nat {
            chain postrouting {
              type nat hook postrouting priority 100; policy accept;
              ip saddr ${var.private_cidr} oifname "eth0" masquerade
            }
          }
    runcmd:
      - sysctl --system
      - systemctl enable --now nftables
      - nft -f /etc/nftables.conf
  EOT
  user_data_final  = lookup(var.legacy_user_data, "${var.prefix}-bastion", "") == local.user_data_legacy ? local.user_data_legacy : local.user_data
}

resource "vmdesktop_vm" "bastion" {
  name        = "${var.prefix}-bastion"
  path        = var.vm_dir
  guest_os_id = var.guest_os_id
  cpus        = var.cpus
  memory_mb   = var.memory_mb
  disk_gb     = var.disk_gb
  base_disk   = var.base_disk

  networks = [
    { type = "nat", mac = local.mac_nat },
    { type = "custom", vmnet = vmdesktop_network.private.name, mac = local.mac_priv },
  ]

  cloud_init = {
    user_data      = local.user_data_final
    meta_data      = "instance-id: ${var.prefix}-bastion\nlocal-hostname: ${var.prefix}-bastion\n"
    network_config = local.network_config
  }

  lifecycle {
    # Checked on create/update plans only (never blocks a destroy). The name is written unquoted into cloud-init's YAML.
    precondition {
      condition     = can(regex("^[A-Za-z_][A-Za-z0-9_.-]{0,31}$", var.ssh_username)) && var.ssh_username != "root" && !contains(["yes", "no", "true", "false", "on", "off", "null"], lower(var.ssh_username))
      error_message = "ssh_username '${var.ssh_username}' cannot be used: 1-32 letters, digits, '_', '.' or '-', starting with a letter or '_'; not root and not a YAML keyword (yes/no/true/false/on/off/null)."
    }
    precondition {
      condition     = var.prefix_len <= 29
      error_message = "The private network ${var.private_cidr} is too small: use a /29 or larger (/24 recommended)."
    }
  }
}

output "nat_ip" { value = vmdesktop_vm.bastion.ip }
output "private_vmnet" { value = vmdesktop_network.private.name }
output "private_vmnet_adopted" { value = vmdesktop_network.private.adopted }
output "vmx_path" { value = vmdesktop_vm.bastion.vmx_path }
