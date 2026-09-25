output "resource_group_name" {
  description = "Resource group holding the environment."
  value       = azurerm_resource_group.this.name
}
output "location" {
  description = "Azure location."
  value       = var.location
}
output "vnet_id" {
  description = "Virtual network ID."
  value       = module.network.vnet_id
}
output "public_subnet_id" {
  description = "Public subnet (bastion)."
  value       = module.network.public_subnet_id
}
output "private_subnet_id" {
  description = "Private subnet for workloads (NAT gateway egress)."
  value       = module.network.private_subnet_id
}
output "nat_public_ip" {
  description = "Public IP your private workloads egress from."
  value       = module.network.nat_public_ip
}
output "bastion_public_ip" {
  description = "Static public IP of the bastion."
  value       = module.bastion.public_ip
}
output "bastion_vm_id" {
  description = "Bastion VM resource ID."
  value       = module.bastion.vm_id
}
output "bastion_instance_id" {
  description = "Unique ID of the bastion VM (vmId); it changes when the VM is re-created behind the same public IP, so cloudseed then forgets the old SSH host key."
  value       = module.bastion.instance_id
}
output "log_analytics_workspace_id" {
  description = "Log Analytics workspace receiving the Activity Log."
  value       = module.security_baseline.log_analytics_workspace_id
}
output "ssh_user" {
  description = "Login user on the bastion."
  value       = var.admin_username
}
output "kubernetes_cluster_name" {
  description = "AKS cluster name (null when disabled)."
  value       = try(module.kubernetes[0].cluster_name, null)
}
output "kubernetes_endpoint" {
  description = "AKS API server FQDN. For a private cluster (the default) a public DNS name of the API server's private IP (<prefix>-<id>.hcp.<region>.azmk8s.io): reachable over the VPN, through the bastion tunnel or inside the VNet, never from the Internet. With kubernetes_public_endpoint = true the public API name (restricted to allowed_ssh_cidrs)."
  value       = try(module.kubernetes[0].endpoint, null)
}
output "vpn_public_ip" {
  description = "Public IP of the VPN host (null when disabled)."
  value       = try(module.vpn[0].public_ip, null)
}
output "vpn_instance_id" {
  description = "Unique ID of the VPN host VM (vmId; null when disabled); it changes when the VM is re-created behind the same public IP."
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
output "kubernetes_external_secrets_client_id" {
  description = "Managed identity (workload identity) for external-secrets; grant it Key Vault Secrets User on your vaults."
  value       = try(module.kubernetes[0].external_secrets_client_id, null)
}

output "kubernetes_external_dns_client_id" {
  description = "Managed identity client ID (workload identity) for external-dns (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].external_dns_client_id, null)
}

output "kubernetes_velero_client_id" {
  description = "Managed identity client ID (workload identity) for velero (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].velero_client_id, null)
}

output "kubernetes_velero_storage_account" {
  description = "Storage account for Velero backups (created when the velero platform item is installed)."
  value       = try(module.kubernetes[0].velero_storage_account, null)
}

output "kubernetes_velero_container" {
  description = "Blob container Velero backs up to (null until the velero platform item is installed)."
  value       = try(module.kubernetes[0].velero_container, null)
}

output "kubernetes_node_resource_group" {
  description = "AKS-managed node resource group, MC_* (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].node_resource_group, null)
}

output "tenant_id" {
  description = "Azure tenant (Entra ID) of the environment; the cluster workload identities are issued there."
  value       = data.azurerm_client_config.current.tenant_id
}

output "subscription_id" {
  description = "Azure subscription holding the environment."
  value       = data.azurerm_client_config.current.subscription_id
}

output "fips_mode" {
  description = "Whether the environment was built in FIPS 140 mode."
  value       = var.fips_mode
}
