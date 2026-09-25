output "account_id" {
  description = "AWS account the environment lives in."
  value       = local.account_id
}

output "region" {
  description = "Region of the stack."
  value       = local.region
}

output "vpc_id" {
  description = "VPC ID."
  value       = module.network.vpc_id
}

output "vpc_cidr" {
  description = "VPC CIDR block."
  value       = module.network.vpc_cidr
}

output "public_subnet_ids" {
  description = "Public subnets (bastion, NAT, load balancers)."
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Private subnets for workloads (egress via NAT)."
  value       = module.network.private_subnet_ids
}

output "data_subnet_ids" {
  description = "Isolated data-tier subnets (no internet route)."
  value       = module.network.data_subnet_ids
}

output "nat_public_ips" {
  description = "Public IPs your private workloads egress from (allow-list these upstream)."
  value       = module.network.nat_public_ips
}

output "bastion_public_ip" {
  description = "Elastic IP of the bastion."
  value       = module.bastion.public_ip
}

output "bastion_instance_id" {
  description = "EC2 instance ID of the bastion."
  value       = module.bastion.instance_id
}

output "bastion_security_group_id" {
  description = "Security group of the bastion."
  value       = module.bastion.security_group_id
}

output "workload_security_group_id" {
  description = "Attach this SG to private workloads; it allows SSH only from the bastion."
  value       = module.bastion.workload_security_group_id
}

output "kms_key_arn" {
  description = "Customer-managed KMS key for logs, CloudTrail, EKS secrets and the bastion/VPN disks."
  value       = module.kms.key_arn
}

output "cloudtrail_bucket" {
  description = "S3 bucket receiving CloudTrail logs and AWS Config snapshots (null when this environment manages neither)."
  value       = try(module.security_baseline[0].cloudtrail_bucket, null)
}

output "ssh_user" {
  description = "Login user on the bastion."
  value       = "ec2-user"
}

output "kubernetes_cluster_name" {
  description = "EKS cluster name (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].cluster_name, null)
}

output "kubernetes_node_group_name" {
  description = "EKS managed node group; resize it through the EKS API, Terraform only sets its initial size (null when disabled)."
  value       = try(module.kubernetes[0].node_group_name, null)
}

output "kubernetes_endpoint" {
  description = "EKS API endpoint (private unless kubernetes_public_endpoint = true)."
  value       = try(module.kubernetes[0].endpoint, null)
}

output "kubernetes_node_role_arn" {
  description = "IAM role of the worker nodes."
  value       = try(module.kubernetes[0].node_role_arn, null)
}

output "kubernetes_oidc_issuer" {
  description = "OIDC issuer URL for IAM Roles for Service Accounts."
  value       = try(module.kubernetes[0].oidc_issuer, null)
}

output "vpn_public_ip" {
  description = "Public IP of the VPN host (null when VPN is disabled)."
  value       = try(module.vpn[0].public_ip, null)
}

output "vpn_instance_id" {
  description = "EC2 instance ID of the VPN host (null when the VPN is disabled)."
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

output "kubernetes_irsa_role_arns" {
  description = "IRSA roles created for platform controllers: ebs-csi, lb-controller, autoscaler, external-secrets."
  value       = try(module.kubernetes[0].irsa_role_arns, {})
}

output "kubernetes_oidc_provider_arn" {
  description = "IAM OIDC provider ARN of the EKS cluster, for IRSA trust policies (null when disabled)."
  value       = try(module.kubernetes[0].oidc_provider_arn, null)
}

output "kubernetes_velero_bucket" {
  description = "S3 bucket for Velero backups (created when the velero platform item is installed)."
  value       = try(module.kubernetes[0].velero_bucket, null)
}

output "kubernetes_karpenter_queue" {
  description = "SQS interruption queue name for Karpenter (null until the karpenter platform item is installed)."
  value       = try(module.kubernetes[0].karpenter_queue, null)
}

output "kubernetes_karpenter_node_role" {
  description = "IAM role name for Karpenter-launched nodes (null until the karpenter platform item is installed)."
  value       = try(module.kubernetes[0].karpenter_node_role, null)
}

output "kubernetes_cluster_security_group_id" {
  description = "EKS-managed cluster security group ID (null when Kubernetes is disabled)."
  value       = try(module.kubernetes[0].cluster_security_group_id, null)
}

output "fips_mode" {
  description = "Whether the environment was built in FIPS 140 mode."
  value       = var.fips_mode
}
