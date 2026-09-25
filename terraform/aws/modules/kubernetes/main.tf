# Private EKS cluster: nodes and (by default) the API endpoint live in the private subnets.
variable "prefix" { type = string }
variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "kubernetes_version" { type = string }
variable "node_instance_type" { type = string }
variable "node_desired" { type = number }
variable "node_min" { type = number }
variable "node_max" { type = number }
variable "public_endpoint" { type = bool }
variable "public_access_cidrs" { type = list(string) }
variable "admin_roles" {
  description = "IAM roles given cluster-admin access entries: plan-time-known key => role ARN."
  type        = map(string)
}
variable "kms_key_arn" { type = string }
variable "log_retention_days" { type = number }
variable "tags" { type = map(string) }
variable "account_id" { type = string }
variable "region" { type = string }
variable "platform_prereqs" {
  description = "Cloud-side prerequisites for optional platform items (created on demand by `cs platform install`): velero, karpenter."
  type        = list(string)
  default     = []
}
variable "fips_mode" {
  description = "FIPS 140 mode: Bottlerocket FIPS node AMIs (FIPS-validated kernel crypto + Go BoringCrypto)."
  type        = bool
  default     = false
}
variable "external_secrets_prefixes" {
  description = "Secret/parameter name prefixes the external-secrets controller may read (null = <prefix>/)."
  type        = list(string)
  default     = null
}

data "aws_partition" "current" {}

locals {
  partition = data.aws_partition.current.partition
  name      = "${var.prefix}-eks"
  arm       = can(regex("^[a-z]+[0-9]+g[a-z]*\\.", var.node_instance_type))
  # Bottlerocket ships FIPS variants of its Kubernetes images; AL2023 has none for EKS node groups.
  ami_type       = var.fips_mode ? (local.arm ? "BOTTLEROCKET_ARM_64_FIPS" : "BOTTLEROCKET_x86_64_FIPS") : (local.arm ? "AL2023_ARM_64_STANDARD" : "AL2023_x86_64_STANDARD")
  want_velero    = contains(var.platform_prereqs, "velero")
  want_karpenter = contains(var.platform_prereqs, "karpenter")
}

# ---- IAM ----
data "aws_iam_policy_document" "cluster_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${local.name}-cluster"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

data "aws_iam_policy_document" "node_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${local.name}-node"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "node" {
  # keyed by the policy ARN: in the commercial partition these are the keys earlier versions used
  for_each = toset([for p in ["AmazonEKSWorkerNodePolicy", "AmazonEC2ContainerRegistryReadOnly", "AmazonEKS_CNI_Policy", "AmazonSSMManagedInstanceCore"] :
  "arn:${local.partition}:iam::aws:policy/${p}"])
  role       = aws_iam_role.node.name
  policy_arn = each.value
}

# ---- Control plane logs (create first so retention + KMS apply) ----
resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${local.name}/cluster"
  retention_in_days = min(var.log_retention_days, 3653)
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# ---- Extra cluster SG: API reachable from inside the VPC ----
# The bastion and the VPN host sit in the VPC's public subnet and the VPN masquerades its clients, so the VPC CIDR rule
# covers all of them (per-SG rules keyed by apply-time SG ids would also break a fresh plan).
resource "aws_security_group" "api" {
  name        = "${local.name}-api-access"
  description = "EKS API access from bastion, VPN and the VPC"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${local.name}-api-access" })
}

resource "aws_vpc_security_group_ingress_rule" "api_from_vpc" {
  security_group_id = aws_security_group.api.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Kubernetes API from inside the VPC"
}

resource "aws_vpc_security_group_egress_rule" "api_all" {
  security_group_id = aws_security_group.api.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ---- Cluster ----
resource "aws_eks_cluster" "this" {
  name     = local.name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = var.public_endpoint
    public_access_cidrs     = var.public_endpoint ? var.public_access_cidrs : null
    security_group_ids      = [aws_security_group.api.id]
  }

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  encryption_config {
    provider {
      key_arn = var.kms_key_arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  tags                      = merge(var.tags, { Name = local.name })

  depends_on = [aws_iam_role_policy_attachment.cluster, aws_cloudwatch_log_group.cluster]
}

# ---- Admin access for the bastion role ----
resource "aws_eks_access_entry" "admin" {
  for_each = var.admin_roles

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  type          = "STANDARD"
  tags          = var.tags
}

resource "aws_eks_access_policy_association" "admin" {
  for_each = var.admin_roles

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  policy_arn    = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }
  depends_on = [aws_eks_access_entry.admin]
}

# ---- Nodes ----
resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${local.name}-default"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.private_subnet_ids
  instance_types  = [var.node_instance_type]
  ami_type        = local.ami_type
  capacity_type   = "ON_DEMAND"
  disk_size       = 50

  scaling_config {
    desired_size = var.node_desired
    min_size     = var.node_min
    max_size     = var.node_max
  }

  update_config {
    max_unavailable = 1
  }

  tags = merge(var.tags, { Name = "${local.name}-default" })

  # desired_size is only the initial size: Terraform never changes it afterwards, so a later apply cannot undo what
  # the EKS API (update-nodegroup-config, output kubernetes_node_group_name) or an autoscaler did. Resize through the
  # API; min/max (kubernetes_node_min/max) do follow the configuration.
  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }

  depends_on = [aws_iam_role_policy_attachment.node]
}

# ---- Core add-ons ----
resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "vpc-cni"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags                        = var.tags
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "kube-proxy"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags                        = var.tags
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "coredns"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags                        = var.tags
  depends_on                  = [aws_eks_node_group.default]
}

output "cluster_name" { value = aws_eks_cluster.this.name }
output "cluster_arn" { value = aws_eks_cluster.this.arn }
output "node_group_name" { value = aws_eks_node_group.default.node_group_name }
output "endpoint" { value = aws_eks_cluster.this.endpoint }
output "node_role_arn" { value = aws_iam_role.node.arn }
output "oidc_issuer" { value = aws_eks_cluster.this.identity[0].oidc[0].issuer }

# ---- Prerequisites for platform controllers: OIDC provider (IRSA) + roles + EBS CSI add-on ----
data "tls_certificate" "oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]
  tags            = var.tags
}

locals {
  oidc_host = replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
  # service accounts that get an IRSA role: name -> {namespace, sa, managed policy arn (optional)}
  irsa = merge({
    ebs-csi          = { ns = "kube-system", sa = "ebs-csi-controller-sa", managed = "arn:${local.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy" }
    lb-controller    = { ns = "kube-system", sa = "aws-load-balancer-controller", managed = null }
    autoscaler       = { ns = "kube-system", sa = "cluster-autoscaler-aws-cluster-autoscaler", managed = null }
    external-secrets = { ns = "external-secrets", sa = "external-secrets", managed = null }
    external-dns     = { ns = "external-dns", sa = "external-dns", managed = null }
    },
    # Velero's chart names its server SA "<release>-server" unless serviceAccount.server.name is set; cloudseed's velero
    # values set it to "velero", which is the subject trusted here (keep the two in step).
    local.want_velero ? { velero = { ns = "velero", sa = "velero", managed = null } } : {},
    local.want_karpenter ? { karpenter = { ns = "kube-system", sa = "karpenter", managed = null } } : {},
  )
}

data "aws_iam_policy_document" "irsa_assume" {
  for_each = local.irsa

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.this.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["system:serviceaccount:${each.value.ns}:${each.value.sa}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "irsa" {
  for_each = local.irsa

  name               = "${local.name}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume[each.key].json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "irsa_managed" {
  for_each = { for k, v in local.irsa : k => v if v.managed != null }

  role       = aws_iam_role.irsa[each.key].name
  policy_arn = each.value.managed
}

# AWS Load Balancer Controller policy: upstream docs/install/iam_policy.json of controller v3.5.0 (the release chart
# 3.5.0 in cloudseed/platform.py deploys; byte-identical to v2.13.0's), vendored so no plan, apply or destroy depends on
# raw.githubusercontent.com. Keep it in step with the chart version. Upstream writes its ARNs for the commercial
# partition; its iam_policy_us-gov.json holds the same statements with arn:aws-us-gov:, which the replace() produces.
resource "aws_iam_role_policy" "lb_controller" {
  name   = "aws-load-balancer-controller"
  role   = aws_iam_role.irsa["lb-controller"].id
  policy = replace(file("${path.module}/lb_controller_iam_policy.json"), "arn:aws:", "arn:${local.partition}:")
}

data "aws_iam_policy_document" "autoscaler" {
  statement {
    actions = [
      "autoscaling:DescribeAutoScalingGroups", "autoscaling:DescribeAutoScalingInstances", "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeScalingActivities", "autoscaling:DescribeTags", "ec2:DescribeInstanceTypes", "ec2:DescribeLaunchTemplateVersions",
      "ec2:DescribeImages", "ec2:GetInstanceTypesFromInstanceRequirements", "eks:DescribeNodegroup",
    ]
    resources = ["*"]
  }
  statement {
    actions   = ["autoscaling:SetDesiredCapacity", "autoscaling:TerminateInstanceInAutoScalingGroup"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/k8s.io/cluster-autoscaler/${local.name}"
      values   = ["owned"]
    }
  }
}

resource "aws_iam_role_policy" "autoscaler" {
  name   = "cluster-autoscaler"
  role   = aws_iam_role.irsa["autoscaler"].id
  policy = data.aws_iam_policy_document.autoscaler.json
}

# external-secrets reads only this environment's secrets: Secrets Manager names and SSM parameter paths starting with
# the prefixes (default "<name>-<env>/", e.g. secret acme-dev/db or parameter /acme-dev/db), not every secret in the
# account. Widen with --var 'external_secrets_prefixes=["shared/","acme-dev/"]' (["*"] = the whole account).
locals {
  eso_prefixes = var.external_secrets_prefixes != null ? var.external_secrets_prefixes : ["${var.prefix}/"]
  eso_paths    = [for p in local.eso_prefixes : trimsuffix(trimprefix(p, "/"), "/")]
}

data "aws_iam_policy_document" "external_secrets" {
  statement {
    sid       = "ReadPrefixedSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [for p in local.eso_prefixes : "arn:${local.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${trimprefix(p, "/")}*"]
  }
  statement {
    sid       = "ReadPrefixedParameters"
    actions   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:ListTagsForResource"]
    resources = flatten([for p in local.eso_paths : ["arn:${local.partition}:ssm:${var.region}:${var.account_id}:parameter/${p}", "arn:${local.partition}:ssm:${var.region}:${var.account_id}:parameter/${p}/*"]])
  }
  statement {
    # List/batch calls have no resource-level scoping; BatchGetSecretValue still needs GetSecretValue on each secret.
    sid       = "ListForFind"
    actions   = ["secretsmanager:ListSecrets", "secretsmanager:BatchGetSecretValue", "ssm:DescribeParameters"]
    resources = ["*"]
  }
  statement {
    sid       = "DecryptThroughSecretStores"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.${data.aws_partition.current.dns_suffix}", "ssm.${var.region}.${data.aws_partition.current.dns_suffix}"]
    }
  }
}

resource "aws_iam_role_policy" "external_secrets" {
  name   = "external-secrets"
  role   = aws_iam_role.irsa["external-secrets"].id
  policy = data.aws_iam_policy_document.external_secrets.json
}

# EKS >= 1.30 no longer marks gp2 as the default StorageClass, so without this every PVC that names no class (MinIO,
# CloudNativePG, Strimzi, Qdrant, ...) stays Pending. The add-on's default class (ebs-csi-default-sc: gp3,
# WaitForFirstConsumer, expandable) becomes the cluster default; volumes are encrypted by the account's EBS
# encryption-by-default (the security baseline turns it on).
resource "aws_eks_addon" "ebs_csi" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "aws-ebs-csi-driver"
  service_account_role_arn    = aws_iam_role.irsa["ebs-csi"].arn
  configuration_values        = jsonencode({ defaultStorageClass = { enabled = true } })
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags                        = var.tags
  depends_on                  = [aws_eks_node_group.default]
}

# Tags the autoscaler discovers the node group by
resource "aws_autoscaling_group_tag" "autoscaler" {
  for_each = toset(["k8s.io/cluster-autoscaler/enabled", "k8s.io/cluster-autoscaler/${local.name}"])

  autoscaling_group_name = aws_eks_node_group.default.resources[0].autoscaling_groups[0].name
  tag {
    key                 = each.value
    value               = "owned"
    propagate_at_launch = false
  }
}

output "oidc_provider_arn" { value = aws_iam_openid_connect_provider.this.arn }
output "irsa_role_arns" { value = { for k, r in aws_iam_role.irsa : k => r.arn } }
