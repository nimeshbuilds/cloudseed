output "project_id" {
  description = "GCP project."
  value       = var.project_id
}
output "region" {
  description = "Region of the stack."
  value       = var.region
}
output "network_name" {
  description = "VPC network name."
  value       = module.network.network_name
}
output "network_self_link" {
  description = "VPC self link (use when attaching resources)."
  value       = module.network.network_self_link
}
output "public_subnet_id" {
  description = "Public subnet (bastion)."
  value       = module.network.public_subnet_id
}
output "private_subnet_id" {
  description = "Private subnet for workloads (Cloud NAT egress)."
  value       = module.network.private_subnet_id
}
output "nat_name" {
  description = "Cloud NAT name."
  value       = module.network.nat_name
}
output "bastion_public_ip" {
  description = "Static external IP of the bastion."
  value       = module.bastion.public_ip
}
output "bastion_name" {
  description = "Bastion instance name."
  value       = module.bastion.name
}
output "bastion_instance_id" {
  description = "Server-assigned ID of the bastion instance (changes when the instance is replaced)."
  value       = module.bastion.instance_id
}
output "bastion_service_account" {
  description = "Service account of the bastion."
  value       = module.bastion.service_account_email
}
output "workload_network_tag" {
  description = "Put this tag on private VMs so the bastion can reach them over SSH."
  value       = module.network.private_tag
}
output "ssh_user" {
  description = "Login user on the bastion and VPN host (the OS Login POSIX username when enable_os_login is on)."
  value       = var.ssh_username
}
output "kubernetes_cluster_name" {
  description = "GKE cluster name (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].cluster_name, null)
}
output "kubernetes_endpoint" {
  description = "GKE control-plane endpoint (private unless kubernetes_public_endpoint = true; null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].endpoint, null)
}
output "kubernetes_location" {
  description = "Zone or region of the cluster, for gcloud container clusters get-credentials (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].location, null)
}
output "kubernetes_node_pool" {
  description = "Name of the GKE node pool, for gcloud container clusters resize / node-pools describe (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].node_pool_name, null)
}
output "kubernetes_master_version" {
  description = "GKE control-plane version as of the last apply: the REGULAR release channel upgrades it past kubernetes_version, which is only a minimum; the bastion's kubectl follows it (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].master_version, null)
}
output "vpn_public_ip" {
  description = "Public IP of the VPN host (null when disabled)."
  value       = try(module.vpn[0].public_ip, null)
}
output "vpn_instance_id" {
  description = "Server-assigned ID of the VPN host instance (null when disabled; changes when the instance is replaced)."
  value       = try(module.vpn[0].instance_id, null)
}
output "vpn_type" {
  description = "VPN flavour on the VPN host: openvpn or tailscale (null when the VPN is disabled)."
  value       = var.enable_vpn ? var.vpn_type : null
}
output "vpn_port" {
  description = "UDP port the VPN host listens on: vpn_port for OpenVPN, 41641 for Tailscale (null when the VPN is disabled)."
  value       = var.enable_vpn ? (var.vpn_type == "tailscale" ? 41641 : var.vpn_port) : null
}
output "kubernetes_external_secrets_gsa" {
  description = "Google service account bound (Workload Identity) to external-secrets/external-secrets (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].external_secrets_gsa, null)
}

output "kubernetes_external_dns_gsa" {
  description = "Google service account bound (Workload Identity) to external-dns/external-dns (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].external_dns_gsa, null)
}

output "kubernetes_velero_gsa" {
  description = "Google service account bound (Workload Identity) to velero/velero (null until the velero platform item is installed, and when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].velero_gsa, null)
}

output "kubernetes_velero_bucket" {
  description = "GCS bucket for Velero backups (null until the velero platform item is installed, and when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].velero_bucket, null)
}

output "fips_mode" {
  description = "Whether the environment was built in FIPS 140 mode."
  value       = var.fips_mode
}

output "kubernetes_master_cidr" {
  description = "GKE control-plane range (outside network_cidr): routed through the VPN so the private API endpoint is reachable (null when Kubernetes is disabled)."
  value       = var.enable_kubernetes ? var.kubernetes_master_cidr : null
}
