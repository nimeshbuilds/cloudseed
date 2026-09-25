variable "prefix" { type = string }
variable "count_vms" { type = number }
variable "vm_dir" { type = string }
variable "base_disk" { type = string }
variable "guest_os_id" { type = string }
variable "private_cidr" { type = string }
variable "private_vmnet" { type = string }
variable "gateway_ip" { type = string }
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
variable "max_vms" {
  description = "Most workload VMs the address plan allows (.10-.19 when Kubernetes also runs: its control planes start at .20)."
  type        = number
  default     = 10
}

terraform {
  required_providers {
    vmdesktop = { source = "registry.local/cloudseed/vmdesktop" }
    random    = { source = "hashicorp/random" }
  }
}

resource "random_integer" "mac" {
  count = var.count_vms * 3
  min   = 0
  max   = 255
}

locals {
  names = [for i in range(var.count_vms) : "${var.prefix}-vm${i + 1}"]
  ips   = [for i in range(var.count_vms) : cidrhost(var.private_cidr, 10 + i)]
  macs = [for i in range(var.count_vms) : format("00:50:56:%02x:%02x:%02x",
  random_integer.mac[i * 3].result % 64, random_integer.mac[i * 3 + 1].result, random_integer.mac[i * 3 + 2].result)]

  # The SSH key as a plain YAML scalar where that is safe, else quoted (JSON strings are valid YAML): a key comment with
  # ': ' or ending in ':' would be read as a mapping and no key installed. (Used by the frozen template below.)
  ssh_key_head = split(" #", var.ssh_public_key)[0]
  ssh_key_yaml = (length(regexall(":([[:space:]]|$)", local.ssh_key_head)) > 0 || length(regexall("[[:cntrl:]]", var.ssh_public_key)) > 0
  ? jsonencode(var.ssh_public_key) : var.ssh_public_key)

  # Workload VMs are never provisioned by Ansible, so cloud-init itself turns their automatic security updates on: the
  # apt timers are off for the first boot only (package installation must not race apt-daily for the dpkg lock) and are
  # unmasked and enabled once the packages are in (runcmd runs after them). unattended-upgrades is not in every image
  # (Debian's), and 20auto-upgrades switches it on. The SSH key is a JSON string (valid YAML): any key comment works.
  user_data = [for i in range(var.count_vms) : <<-EOT
    #cloud-config
    bootcmd:
      - [cloud-init-per, instance, cloudseed-apt-off, sh, -c, "systemctl disable --now apt-daily.timer apt-daily-upgrade.timer; systemctl mask apt-daily.service apt-daily-upgrade.service"]
    hostname: ${local.names[i]}
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
    packages: ${jsonencode(concat(["open-vm-tools", "unattended-upgrades"], var.packages))}
    write_files:
      - path: /etc/apt/apt.conf.d/20auto-upgrades
        defer: true
        content: |
          APT::Periodic::Update-Package-Lists "1";
          APT::Periodic::Unattended-Upgrade "1";
    runcmd:
      - [systemctl, unmask, apt-daily.service, apt-daily-upgrade.service]
      - [systemctl, enable, --now, apt-daily.timer, apt-daily-upgrade.timer]
  EOT
  ]

  # FROZEN - the previous template, byte for byte (it masked the apt timers on every boot, for good). Any change to a
  # VM's cloud-init rebuilds it, so a workload VM created from it keeps it (see user_data_final); do not edit. Its key is
  # quoted only where the plain form was broken anyway (a comment with ': ', or ending in ':').
  user_data_legacy = [for i in range(var.count_vms) : <<-EOT
      #cloud-config
      bootcmd:
        - [systemctl, disable, --now, apt-daily.timer, apt-daily-upgrade.timer]
        - [systemctl, mask, apt-daily.service, apt-daily-upgrade.service]
      hostname: ${local.names[i]}
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
      packages: ${jsonencode(concat(["open-vm-tools"], var.packages))}
    EOT
  ]
  user_data_final = [for i in range(var.count_vms) :
  lookup(var.legacy_user_data, local.names[i], "") == local.user_data_legacy[i] ? local.user_data_legacy[i] : local.user_data[i]]
}

resource "vmdesktop_vm" "workload" {
  count = var.count_vms

  name        = local.names[count.index]
  path        = var.vm_dir
  guest_os_id = var.guest_os_id
  cpus        = var.cpus
  memory_mb   = var.memory_mb
  disk_gb     = var.disk_gb
  base_disk   = var.base_disk
  # Private NIC only: no DHCP lease, so don't wait for a tools-reported IP.
  wait_for_ip_seconds = 0

  networks = [
    { type = "custom", vmnet = var.private_vmnet, mac = local.macs[count.index] },
  ]

  cloud_init = {
    user_data = local.user_data_final[count.index]
    meta_data = "instance-id: ${local.names[count.index]}\nlocal-hostname: ${local.names[count.index]}\n"
    network_config = yamlencode({
      version = 2
      ethernets = {
        priv = {
          match       = { macaddress = local.macs[count.index] }
          set-name    = "eth0"
          addresses   = ["${local.ips[count.index]}/${var.prefix_len}"]
          routes      = [{ to = "default", via = var.gateway_ip }]
          nameservers = { addresses = ["1.1.1.1", "8.8.8.8"] }
        }
      }
    })
  }

  lifecycle {
    precondition {
      condition     = count.index > 0 || var.count_vms <= var.max_vms
      error_message = "workload_count can be at most ${var.max_vms} here (static addresses from .10; with Kubernetes on, its control planes start at .20)."
    }
  }
}

output "private_ips" { value = local.ips }
output "names" { value = local.names }
