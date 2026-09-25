output "host_product" {
  description = "fusion or workstation."
  value       = data.vmdesktop_host.this.product
}

output "host_version" {
  description = "VMware Fusion/Workstation version reported by the host."
  value       = data.vmdesktop_host.this.version
}

output "guest_arch" {
  description = "Guest architecture this host runs (arm64 / amd64)."
  value       = data.vmdesktop_host.this.guest_arch
}

output "private_vmnet" {
  description = "Host-only vmnet of the private network."
  value       = module.bastion.private_vmnet
}

output "private_vmnet_adopted" {
  description = "true when the private vmnet existed before (adopted, e.g. vmnet1) and must be kept on destroy; false when this stack created it; null for networks recorded before this was tracked."
  value       = module.bastion.private_vmnet_adopted
}

output "private_cidr" {
  description = "CIDR of the host-only private network."
  value       = var.private_cidr
}

output "bastion_public_ip" {
  description = "Bastion address on the NAT network (reachable from this machine)."
  value       = module.bastion.nat_ip
}

output "bastion_private_ip" {
  description = "Bastion address on the private network (gateway for workloads)."
  value       = local.bastion_priv_ip
}

output "workload_private_ips" {
  description = "Private IPs of the workload VMs (reach them through the bastion)."
  value       = module.workloads.private_ips
}

output "workload_names" {
  description = "Names of the workload VMs."
  value       = module.workloads.names
}

output "ssh_user" {
  description = "Login user on the bastion."
  value       = var.ssh_username
}

output "kubernetes_distro" {
  description = "rke2 or kubeadm (null when Kubernetes is disabled)."
  value       = var.enable_kubernetes ? var.kubernetes_distro : null
}

output "kubernetes_control_plane_ips" {
  description = "Private IPs of the control-plane VMs."
  value       = try(module.kubernetes[0].control_plane_ips, [])
}

output "kubernetes_worker_ips" {
  description = "Private IPs of the worker VMs."
  value       = try(module.kubernetes[0].worker_ips, [])
}

output "kubernetes_endpoint" {
  description = "API server URL (reachable from this machine over the host-only network)."
  value       = try("https://${module.kubernetes[0].control_plane_ips[0]}:6443", null)
}

output "fips_mode" {
  description = "Whether the environment was built in FIPS 140 mode."
  value       = var.fips_mode
}
