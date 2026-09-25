# cloudseed AWS stack: network + bastion + account security baseline.

data "aws_availability_zones" "available" {
  state = "available"
  # AZs that cannot host the EKS control plane are skipped when Kubernetes is on. Matched by AZ id: AZ names map to
  # different physical zones in every account.
  exclude_zone_ids = var.enable_kubernetes ? local.eks_unsupported_zone_ids : []
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
  lifecycle {
    postcondition {
      condition     = length(self.names) >= var.az_count
      error_message = "az_count = ${var.az_count}, but this region has only ${length(self.names)} usable availability zone(s) (${join(", ", self.names)})${var.enable_kubernetes ? " that can host EKS" : ""}: lower az_count."
    }
  }
}

# Same query without the EKS exclusion, only to tell when the exclusion moved the subnets to other AZs.
data "aws_availability_zones" "all" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

check "eks_availability_zones" {
  assert {
    condition = !var.enable_kubernetes || length(setsubtract(
      slice(data.aws_availability_zones.all.names, 0, min(var.az_count, length(data.aws_availability_zones.all.names))),
    local.azs)) == 0
    error_message = "Some of the first ${var.az_count} availability zones cannot host the EKS control plane, so the subnets use ${join(", ", local.azs)}. On an environment that already has subnets in the skipped zones this plan replaces them (with the bastion/NAT in them)."
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
# Every ARN is built from the partition of the credentials. The stack targets the commercial partition and GovCloud;
# China and the isolated regions differ in more than their ARNs (service principals, endpoints, images). `cloudseed
# setup` refuses those regions; this check warns anyone using the module directly (a warning, so debris left there by
# an earlier version can still be destroyed).
data "aws_partition" "current" {}

check "supported_partition" {
  assert {
    condition     = contains(["aws", "aws-us-gov"], data.aws_partition.current.partition)
    error_message = "The ${data.aws_partition.current.partition} partition (region ${data.aws_region.current.region}) is not supported: cloudseed's AWS stack is built for the commercial regions and GovCloud (us-gov-east-1, us-gov-west-1)."
  }
}

locals {
  prefix     = "${var.name}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  azs        = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  # AZ ids where EKS does not support control planes (Amazon EKS user guide, "Cluster VPC and subnet requirements").
  eks_unsupported_zone_ids = ["use1-az3", "usw1-az2", "cac1-az3"]
  # The security baseline has an account-wide half (one environment per account) and a regional half (one environment
  # per account and region); the regional half follows the account switch unless set on its own.
  regional_baseline = var.enable_regional_baseline != null ? var.enable_regional_baseline : var.enable_account_baseline
  # AWS Config records (and delivers to the baseline's log bucket) whenever Security Hub is on, unless turned off.
  enable_aws_config = local.regional_baseline && (var.enable_aws_config != null ? var.enable_aws_config : var.enable_security_hub)
  # Environment is only a default: a --tag Environment=... (in var.tags) applies to every resource, as on GCP and Azure.
  # ManagedBy comes last, so it always says cloudseed.
  tags = merge({ Environment = var.environment }, var.tags, { ManagedBy = "cloudseed" })
}

module "kms" {
  source = "./modules/kms"

  prefix                  = local.prefix
  account_id              = local.account_id
  region                  = local.region
  deletion_window_in_days = var.kms_deletion_window_in_days
  allow_aws_config        = local.enable_aws_config
  tags                    = local.tags
}

module "network" {
  source = "./modules/network"

  prefix                  = local.prefix
  vpc_cidr                = var.vpc_cidr
  azs                     = local.azs
  subnet_newbits          = var.subnet_newbits
  subnet_stride           = var.subnet_stride
  single_nat_gateway      = var.single_nat_gateway
  create_data_subnets     = var.create_data_subnets
  enable_flow_logs        = var.enable_flow_logs
  flow_log_retention_days = var.flow_log_retention_days
  kms_key_arn             = module.kms.key_arn
  tags                    = local.tags
}

module "bastion" {
  source = "./modules/bastion"

  prefix            = local.prefix
  vpc_id            = module.network.vpc_id
  vpc_cidr          = module.network.vpc_cidr
  subnet_id         = module.network.public_subnet_ids[0]
  allowed_ssh_cidrs = var.allowed_ssh_cidrs
  ssh_public_key    = var.ssh_public_key
  instance_type     = var.bastion_instance_type
  root_volume_size  = var.bastion_root_volume_size
  kms_key_arn       = module.kms.key_arn
  tags              = local.tags
}

module "security_baseline" {
  count  = var.enable_account_baseline || local.regional_baseline ? 1 : 0
  source = "./modules/security-baseline"

  prefix                 = local.prefix
  account_id             = local.account_id
  region                 = local.region
  kms_key_arn            = module.kms.key_arn
  manage_account         = var.enable_account_baseline
  manage_region          = local.regional_baseline
  enable_cloudtrail      = var.enable_cloudtrail
  enable_guardduty       = var.enable_guardduty
  enable_access_analyzer = var.enable_access_analyzer
  enable_security_hub    = var.enable_security_hub
  enable_aws_config      = local.enable_aws_config
  log_retention_days     = var.log_retention_days
  tags                   = local.tags
}

module "kubernetes" {
  count  = var.enable_kubernetes ? 1 : 0
  source = "./modules/kubernetes"

  prefix              = local.prefix
  vpc_id              = module.network.vpc_id
  vpc_cidr            = module.network.vpc_cidr
  private_subnet_ids  = module.network.private_subnet_ids
  kubernetes_version  = var.kubernetes_version
  node_instance_type  = var.kubernetes_node_size
  node_desired        = var.kubernetes_node_count
  node_min            = var.kubernetes_node_min
  node_max            = var.kubernetes_node_max
  public_endpoint     = var.kubernetes_public_endpoint
  public_access_cidrs = var.allowed_ssh_cidrs
  # Cluster-admin access entries. Keys must be known at plan time (for_each), so they are the role ARN built from its
  # name (identical to the real ARN, so existing entries keep their address); values carry the dependency on the role.
  # Only the bastion: the VPN host faces the internet and needs no cluster access (VPN users bring their own).
  admin_roles = {
    "arn:${local.partition}:iam::${local.account_id}:role/${local.prefix}-bastion" = module.bastion.iam_role_arn
  }
  kms_key_arn               = module.kms.key_arn
  log_retention_days        = var.log_retention_days
  account_id                = local.account_id
  region                    = local.region
  platform_prereqs          = var.platform_prereqs
  external_secrets_prefixes = var.external_secrets_prefixes
  fips_mode                 = var.fips_mode
  tags                      = local.tags
}

# The bastion's cluster-admin access entry needs the IAM side too: `aws eks update-kubeconfig` on the bastion (as its
# instance role) reads the endpoint and CA with eks:DescribeCluster. `aws eks get-token` needs no IAM permission.
resource "aws_iam_role_policy" "bastion_eks" {
  count = var.enable_kubernetes ? 1 : 0

  name = "eks-describe-cluster"
  role = module.bastion.iam_role_name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["eks:DescribeCluster"], Resource = module.kubernetes[0].cluster_arn }]
  })
}

module "vpn" {
  count  = var.enable_vpn ? 1 : 0
  source = "./modules/vpn"

  prefix                     = local.prefix
  vpc_id                     = module.network.vpc_id
  vpc_cidr                   = module.network.vpc_cidr
  subnet_id                  = module.network.public_subnet_ids[0]
  vpn_type                   = var.vpn_type
  vpn_port                   = var.vpn_port
  allowed_ssh_cidrs          = var.allowed_ssh_cidrs
  bastion_security_group_id  = module.bastion.security_group_id
  workload_security_group_id = module.bastion.workload_security_group_id
  key_name                   = module.bastion.key_name
  instance_type              = var.vpn_instance_type
  kms_key_arn                = module.kms.key_arn
  tags                       = local.tags
}
