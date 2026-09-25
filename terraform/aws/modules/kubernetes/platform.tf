# Cloud-side prerequisites for platform items installed by `cs platform install`: identities, buckets, queues and the
# discovery tags each controller needs. Identities are free and always created; storage/queues only when the item is
# requested (var.platform_prereqs), so nothing accrues cost until the item is actually used.

# ---- external-dns: Route53 records in this account ----
data "aws_iam_policy_document" "external_dns" {
  statement {
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = ["arn:${local.partition}:route53:::hostedzone/*"]
  }
  statement {
    actions   = ["route53:ListHostedZones", "route53:ListResourceRecordSets", "route53:ListTagsForResource"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "external_dns" {
  name   = "external-dns"
  role   = aws_iam_role.irsa["external-dns"].id
  policy = data.aws_iam_policy_document.external_dns.json
}

# ---- velero: backups in a hardened S3 bucket + EBS snapshots ----
resource "aws_s3_bucket" "velero" {
  count         = local.want_velero ? 1 : 0
  bucket        = "${lower(local.name)}-velero-${var.account_id}"
  force_destroy = true
  tags          = merge(var.tags, { Name = "${local.name}-velero" })
}

resource "aws_s3_bucket_versioning" "velero" {
  count  = local.want_velero ? 1 : 0
  bucket = aws_s3_bucket.velero[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "velero" {
  count  = local.want_velero ? 1 : 0
  bucket = aws_s3_bucket.velero[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "velero" {
  count                   = local.want_velero ? 1 : 0
  bucket                  = aws_s3_bucket.velero[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "velero_bucket" {
  count = local.want_velero ? 1 : 0
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.velero[0].arn, "${aws_s3_bucket.velero[0].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "velero" {
  count  = local.want_velero ? 1 : 0
  bucket = aws_s3_bucket.velero[0].id
  policy = data.aws_iam_policy_document.velero_bucket[0].json
}

data "aws_iam_policy_document" "velero" {
  count = local.want_velero ? 1 : 0
  statement {
    actions   = ["ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:CreateTags", "ec2:CreateVolume", "ec2:CreateSnapshot", "ec2:DeleteSnapshot"]
    resources = ["*"]
  }
  statement {
    actions   = ["s3:GetObject", "s3:DeleteObject", "s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
    resources = ["${aws_s3_bucket.velero[0].arn}/*"]
  }
  statement {
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.velero[0].arn]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "velero" {
  count  = local.want_velero ? 1 : 0
  name   = "velero"
  role   = aws_iam_role.irsa["velero"].id
  policy = data.aws_iam_policy_document.velero[0].json
}

# ---- karpenter: controller role, node role + instance profile, interruption queue, discovery tags ----
resource "aws_iam_role" "karpenter_node" {
  count = local.want_karpenter ? 1 : 0
  name  = "${local.name}-karpenter-node"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "karpenter_node" {
  for_each = local.want_karpenter ? toset([for p in ["AmazonEKSWorkerNodePolicy", "AmazonEC2ContainerRegistryReadOnly", "AmazonEKS_CNI_Policy", "AmazonSSMManagedInstanceCore"] :
  "arn:${local.partition}:iam::aws:policy/${p}"]) : toset([])
  role       = aws_iam_role.karpenter_node[0].name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "karpenter_node" {
  count = local.want_karpenter ? 1 : 0
  name  = "${local.name}-karpenter-node"
  role  = aws_iam_role.karpenter_node[0].name
  tags  = var.tags
}

resource "aws_eks_access_entry" "karpenter_node" {
  count         = local.want_karpenter ? 1 : 0
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_iam_role.karpenter_node[0].arn
  type          = "EC2_LINUX"
  tags          = var.tags
}

resource "aws_sqs_queue" "karpenter" {
  count                     = local.want_karpenter ? 1 : 0
  name                      = "${local.name}-karpenter"
  message_retention_seconds = 300
  sqs_managed_sse_enabled   = true
  tags                      = var.tags
}

data "aws_iam_policy_document" "karpenter_queue" {
  count = local.want_karpenter ? 1 : 0
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.karpenter[0].arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "sqs.amazonaws.com"]
    }
  }
}

resource "aws_sqs_queue_policy" "karpenter" {
  count     = local.want_karpenter ? 1 : 0
  queue_url = aws_sqs_queue.karpenter[0].id
  policy    = data.aws_iam_policy_document.karpenter_queue[0].json
}

locals {
  karpenter_events = {
    scheduled-change = { source = "aws.health", detail-type = "AWS Health Event" }
    spot-interrupt   = { source = "aws.ec2", detail-type = "EC2 Spot Instance Interruption Warning" }
    rebalance        = { source = "aws.ec2", detail-type = "EC2 Instance Rebalance Recommendation" }
    state-change     = { source = "aws.ec2", detail-type = "EC2 Instance State-change Notification" }
  }
}

resource "aws_cloudwatch_event_rule" "karpenter" {
  for_each      = local.want_karpenter ? local.karpenter_events : {}
  name          = "${local.name}-karpenter-${each.key}"
  event_pattern = jsonencode({ source = [each.value.source], detail-type = [each.value.detail-type] })
  tags          = var.tags
}

resource "aws_cloudwatch_event_target" "karpenter" {
  for_each = local.want_karpenter ? local.karpenter_events : {}
  rule     = aws_cloudwatch_event_rule.karpenter[each.key].name
  arn      = aws_sqs_queue.karpenter[0].arn
}

# Controller policy after the upstream Karpenter v1 CloudFormation policy: everything that creates, tags or deletes
# instances, launch templates and instance profiles is scoped to resources carrying this cluster's ownership tag and a
# Karpenter nodepool/nodeclass tag, so the controller cannot terminate the bastion, the VPN host or other environments'
# instances. Read-only calls stay unscoped (region-limited).
locals {
  karpenter_arn     = "arn:${local.partition}:ec2:${var.region}"
  karpenter_owned   = "aws:ResourceTag/kubernetes.io/cluster/${local.name}"
  karpenter_request = "aws:RequestTag/kubernetes.io/cluster/${local.name}"
  karpenter_created = [for r in ["fleet", "instance", "volume", "network-interface", "launch-template", "spot-instances-request"] : "${local.karpenter_arn}:*:${r}/*"]
  instance_profiles = "arn:${local.partition}:iam::${var.account_id}:instance-profile/*"
}

data "aws_iam_policy_document" "karpenter_controller" {
  count = local.want_karpenter ? 1 : 0
  statement {
    sid     = "LaunchIntoSharedResources"
    actions = ["ec2:RunInstances", "ec2:CreateFleet"]
    resources = [
      "${local.karpenter_arn}::image/*", "${local.karpenter_arn}::snapshot/*", "${local.karpenter_arn}:*:security-group/*",
      "${local.karpenter_arn}:*:subnet/*", "${local.karpenter_arn}:*:capacity-reservation/*", "${local.karpenter_arn}:*:placement-group/*",
    ]
  }
  statement {
    sid       = "LaunchFromOwnLaunchTemplates"
    actions   = ["ec2:RunInstances", "ec2:CreateFleet"]
    resources = ["${local.karpenter_arn}:*:launch-template/*"]
    condition {
      test     = "StringEquals"
      variable = local.karpenter_owned
      values   = ["owned"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }
  statement {
    sid       = "CreateTaggedResources"
    actions   = ["ec2:RunInstances", "ec2:CreateFleet", "ec2:CreateLaunchTemplate"]
    resources = local.karpenter_created
    condition {
      test     = "StringEquals"
      variable = local.karpenter_request
      values   = ["owned"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }
  statement {
    sid       = "TagOnCreate"
    actions   = ["ec2:CreateTags"]
    resources = local.karpenter_created
    condition {
      test     = "StringEquals"
      variable = local.karpenter_request
      values   = ["owned"]
    }
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["RunInstances", "CreateFleet", "CreateLaunchTemplate"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }
  statement {
    sid       = "TagOwnInstances"
    actions   = ["ec2:CreateTags"]
    resources = ["${local.karpenter_arn}:*:instance/*"]
    condition {
      test     = "StringEquals"
      variable = local.karpenter_owned
      values   = ["owned"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = ["eks:eks-cluster-name", "karpenter.sh/nodeclaim", "Name"]
    }
  }
  statement {
    sid       = "DeleteOwnResources"
    actions   = ["ec2:TerminateInstances", "ec2:DeleteLaunchTemplate"]
    resources = ["${local.karpenter_arn}:*:instance/*", "${local.karpenter_arn}:*:launch-template/*"]
    condition {
      test     = "StringEquals"
      variable = local.karpenter_owned
      values   = ["owned"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }
  statement {
    sid       = "RegionalReads"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }
  }
  statement {
    sid       = "PublicImageParameters"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:${local.partition}:ssm:${var.region}::parameter/aws/service/*"]
  }
  statement {
    sid       = "Pricing"
    actions   = ["pricing:GetProducts"]
    resources = ["*"]
  }
  statement {
    sid       = "ClusterEndpoint"
    actions   = ["eks:DescribeCluster"]
    resources = [aws_eks_cluster.this.arn]
  }
  statement {
    sid       = "PassNodeRole"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.karpenter_node[0].arn]
  }
  statement {
    sid       = "CreateOwnInstanceProfiles"
    actions   = ["iam:CreateInstanceProfile"]
    resources = [local.instance_profiles]
    condition {
      test     = "StringEquals"
      variable = local.karpenter_request
      values   = ["owned"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/topology.kubernetes.io/region"
      values   = [var.region]
    }
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass"
      values   = ["*"]
    }
  }
  statement {
    sid       = "TagOwnInstanceProfiles"
    actions   = ["iam:TagInstanceProfile"]
    resources = [local.instance_profiles]
    condition {
      test     = "StringEquals"
      variable = local.karpenter_owned
      values   = ["owned"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/topology.kubernetes.io/region"
      values   = [var.region]
    }
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass"
      values   = ["*"]
    }
  }
  statement {
    sid       = "ManageOwnInstanceProfiles"
    actions   = ["iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile", "iam:DeleteInstanceProfile"]
    resources = [local.instance_profiles]
    condition {
      test     = "StringEquals"
      variable = local.karpenter_owned
      values   = ["owned"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/topology.kubernetes.io/region"
      values   = [var.region]
    }
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass"
      values   = ["*"]
    }
  }
  statement {
    sid       = "ReadInstanceProfiles"
    actions   = ["iam:GetInstanceProfile", "iam:ListInstanceProfiles"]
    resources = ["*"]
  }
  statement {
    sid       = "Interruptions"
    actions   = ["sqs:DeleteMessage", "sqs:GetQueueUrl", "sqs:ReceiveMessage"]
    resources = [aws_sqs_queue.karpenter[0].arn]
  }
}

resource "aws_iam_role_policy" "karpenter_controller" {
  count  = local.want_karpenter ? 1 : 0
  name   = "karpenter-controller"
  role   = aws_iam_role.irsa["karpenter"].id
  policy = data.aws_iam_policy_document.karpenter_controller[0].json
}

# Karpenter discovers subnets and security groups by this tag (EC2NodeClass selectors). count, not for_each: the subnet
# ids are unknown until the network is applied, but their number is not.
resource "aws_ec2_tag" "karpenter_subnet" {
  count       = local.want_karpenter ? length(var.private_subnet_ids) : 0
  resource_id = var.private_subnet_ids[count.index]
  key         = "karpenter.sh/discovery"
  value       = local.name
}

# The earlier for_each version is forgotten, not destroyed: deleting it would race the identical tags created above.
removed {
  from = aws_ec2_tag.karpenter_subnets
  lifecycle {
    destroy = false
  }
}

resource "aws_ec2_tag" "karpenter_cluster_sg" {
  count       = local.want_karpenter ? 1 : 0
  resource_id = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  key         = "karpenter.sh/discovery"
  value       = local.name
}

output "velero_bucket" { value = local.want_velero ? aws_s3_bucket.velero[0].id : null }
output "karpenter_queue" { value = local.want_karpenter ? aws_sqs_queue.karpenter[0].name : null }
output "karpenter_node_role" { value = local.want_karpenter ? aws_iam_role.karpenter_node[0].name : null }
output "cluster_security_group_id" { value = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id }
