# Kubernetes node VMs on the private network (private NIC only, egress via the bastion).
# The cluster itself (RKE2 or kubeadm) is installed by ansible/kubernetes.yml from the host.
variable "prefix" { type = string }
variable "vm_dir" { type = string }
variable "base_disk" { type = string }
variable "guest_os_id" { type = string }
variable "private_cidr" { type = string }
variable "private_vmnet" { type = string }
variable "gateway_ip" { type = string }
variable "prefix_len" { type = number }
variable "control_planes" { type = number }
variable "workers" { type = number }
variable "cpus" { type = number }
variable "memory_mb" { type = number }
variable "disk_gb" { type = number }
variable "ssh_public_key" { type = string }
variable "ssh_username" { type = string }
variable "max_host" {
  description = "Highest host number a static address may use (below VMware's DHCP pool and inside the subnet)."
  type        = number
  default     = 127
}

terraform {
  required_providers {
    vmdesktop = { source = "registry.local/cloudseed/vmdesktop" }
    random    = { source = "hashicorp/random" }
  }
}

# Nodes are keyed by their short name (cp1.., wk1..), never by position: adding a control plane must not shift the
# workers onto other indexes (which would rename, re-address and so rebuild every worker VM).
# Fixed address blocks: control planes .20-.39, workers .40 up to max_host.
locals {
  nodes = merge(
    { for i in range(var.control_planes) : "cp${i + 1}" => { name = "${var.prefix}-cp${i + 1}", ip = cidrhost(var.private_cidr, 20 + i), role = "control-plane" } },
    { for i in range(var.workers) : "wk${i + 1}" => { name = "${var.prefix}-wk${i + 1}", ip = cidrhost(var.private_cidr, 40 + i), role = "worker" } },
  )
  cp_keys = [for i in range(var.control_planes) : "cp${i + 1}"]
  wk_keys = [for i in range(var.workers) : "wk${i + 1}"]
}

resource "random_integer" "mac" {
  for_each = toset(flatten([for k in keys(local.nodes) : ["${k}-0", "${k}-1", "${k}-2"]]))
  min      = 0
  max      = 255
}

locals {
  macs = { for k in keys(local.nodes) : k => format("00:50:56:%02x:%02x:%02x",
  random_integer.mac["${k}-0"].result % 64, random_integer.mac["${k}-1"].result, random_integer.mac["${k}-2"].result) }

  # The SSH key as a YAML scalar: quoted (JSON strings are valid YAML) where the plain form breaks - a key comment with
  # ': ' or ending in ':' would be read as a mapping and no key installed. Every other key is written as before: any
  # change to a node's cloud-init rebuilds it. (The apt timers stay masked on nodes: their upgrades are deliberate.)
  ssh_key_head = split(" #", var.ssh_public_key)[0]
  ssh_key_yaml = (length(regexall(":([[:space:]]|$)", local.ssh_key_head)) > 0 || length(regexall("[[:cntrl:]]", var.ssh_public_key)) > 0
  ? jsonencode(var.ssh_public_key) : var.ssh_public_key)
}

resource "vmdesktop_vm" "node" {
  for_each = local.nodes

  name                = each.value.name
  path                = var.vm_dir
  guest_os_id         = var.guest_os_id
  cpus                = var.cpus
  memory_mb           = var.memory_mb
  disk_gb             = var.disk_gb
  base_disk           = var.base_disk
  wait_for_ip_seconds = 0

  networks = [
    { type = "custom", vmnet = var.private_vmnet, mac = local.macs[each.key] },
  ]

  cloud_init = {
    user_data = <<-EOT
      #cloud-config
      bootcmd:
        - [systemctl, disable, --now, apt-daily.timer, apt-daily-upgrade.timer]
        - [systemctl, mask, apt-daily.service, apt-daily-upgrade.service]
      hostname: ${each.value.name}
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
      packages: [open-vm-tools, curl, apt-transport-https, ca-certificates, gnupg]
    EOT
    meta_data = "instance-id: ${each.value.name}\nlocal-hostname: ${each.value.name}\n"
    network_config = yamlencode({
      version = 2
      ethernets = {
        priv = {
          match       = { macaddress = local.macs[each.key] }
          set-name    = "eth0"
          addresses   = ["${each.value.ip}/${var.prefix_len}"]
          routes      = [{ to = "default", via = var.gateway_ip }]
          nameservers = { addresses = ["1.1.1.1", "8.8.8.8"] }
        }
      }
    })
  }

  # Checked on create/update plans only (never blocks a destroy); reported once, on the first node.
  lifecycle {
    precondition {
      condition     = each.key != keys(local.nodes)[0] || (var.control_planes >= 1 && var.control_planes <= 20 && 20 + var.control_planes - 1 <= var.max_host)
      error_message = "kubernetes_control_planes must be 1-${min(20, max(var.max_host - 19, 0))} on ${var.private_cidr} (static addresses from .20; at most .39)."
    }
    precondition {
      condition     = each.key != keys(local.nodes)[0] || var.workers == 0 || (var.workers > 0 && 40 + var.workers - 1 <= var.max_host)
      error_message = "kubernetes_workers can be at most ${max(var.max_host - 39, 0)} on ${var.private_cidr} (static addresses .40-.${var.max_host}, below VMware's DHCP pool)."
    }
  }
}

# In node order (cp1..cpN, wk1..wkN): provisioning pairs these lists by position.
output "control_plane_ips" { value = [for k in local.cp_keys : local.nodes[k].ip] }
output "worker_ips" { value = [for k in local.wk_keys : local.nodes[k].ip] }
output "node_names" { value = [for k in concat(local.cp_keys, local.wk_keys) : local.nodes[k].name] }
