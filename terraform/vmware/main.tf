# cloudseed local stack on VMware Fusion Pro / Workstation Pro:
# bastion (NAT NIC + private NIC, acts as gateway) and optional private workload VMs.

data "vmdesktop_host" "this" {}

# Internal input, not a setting (so not in variables.tf): cloudseed derives it from the Terraform state - the recorded
# first-boot user-data of this environment's VMs that an earlier template created, by VM name. Any change to a VM's
# cloud-init rebuilds it, so the modules keep rendering that template for those VMs; an upgrade never rebuilds them.
variable "legacy_user_data" {
  type    = map(string)
  default = {}
}

locals {
  prefix          = "${var.name}-${var.environment}"
  bastion_priv_ip = cidrhost(var.private_cidr, 2)
  prefix_len      = tonumber(split("/", var.private_cidr)[1])
  # Static address plan: bastion .2, workloads .10+, control planes .20-.39, workers .40+. Every static address stays
  # at or below .127 (VMware's host-only DHCP pool starts at .128) and inside the subnet.
  max_host = min(127, pow(2, 32 - local.prefix_len) - 2)
}

module "bastion" {
  source = "./modules/bastion"

  prefix         = local.prefix
  vm_dir         = var.vm_dir
  base_disk      = var.base_disk
  guest_os_id    = var.guest_os_id
  private_cidr   = var.private_cidr
  private_ip     = local.bastion_priv_ip
  prefix_len     = local.prefix_len
  cpus           = var.bastion_cpus
  memory_mb      = var.bastion_memory_mb
  disk_gb        = var.bastion_disk_gb
  ssh_public_key = var.ssh_public_key
  ssh_username   = var.ssh_username
  packages       = var.packages

  legacy_user_data = var.legacy_user_data
}

module "workloads" {
  source = "./modules/workloads"

  prefix         = local.prefix
  count_vms      = var.workload_count
  vm_dir         = var.vm_dir
  base_disk      = var.base_disk
  guest_os_id    = var.guest_os_id
  private_cidr   = var.private_cidr
  private_vmnet  = module.bastion.private_vmnet
  gateway_ip     = local.bastion_priv_ip
  prefix_len     = local.prefix_len
  max_vms        = var.enable_kubernetes ? 10 : max(local.max_host - 9, 0)
  cpus           = var.workload_cpus
  memory_mb      = var.workload_memory_mb
  disk_gb        = var.workload_disk_gb
  ssh_public_key = var.ssh_public_key
  ssh_username   = var.ssh_username
  packages       = var.packages

  legacy_user_data = var.legacy_user_data
}

module "kubernetes" {
  count  = var.enable_kubernetes ? 1 : 0
  source = "./modules/kubernetes"

  prefix         = local.prefix
  vm_dir         = var.vm_dir
  base_disk      = var.base_disk
  guest_os_id    = var.guest_os_id
  private_cidr   = var.private_cidr
  private_vmnet  = module.bastion.private_vmnet
  gateway_ip     = local.bastion_priv_ip
  prefix_len     = local.prefix_len
  control_planes = var.kubernetes_control_planes
  workers        = var.kubernetes_workers
  max_host       = local.max_host
  cpus           = var.kubernetes_cpus
  memory_mb      = var.kubernetes_memory_mb
  disk_gb        = var.kubernetes_disk_gb
  ssh_public_key = var.ssh_public_key
  ssh_username   = var.ssh_username
}
