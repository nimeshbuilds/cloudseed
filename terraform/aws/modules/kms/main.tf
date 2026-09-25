variable "prefix" { type = string }
variable "account_id" { type = string }
variable "region" { type = string }
variable "deletion_window_in_days" { type = number }
variable "tags" { type = map(string) }
variable "allow_aws_config" {
  description = "Let AWS Config encrypt the snapshots it delivers to the (CMK-encrypted) log bucket."
  type        = bool
  default     = false
}

# ARNs are built for the partition the credentials belong to (aws, or aws-us-gov in GovCloud): a key policy naming an
# arn:aws: principal is refused as invalid outside the commercial partition.
data "aws_partition" "current" {}

locals {
  partition = data.aws_partition.current.partition
}

data "aws_iam_policy_document" "key" {
  statement {
    sid    = "EnableRootAndIamPermissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${var.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.${data.aws_partition.current.dns_suffix}"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${var.region}:${var.account_id}:log-group:*"]
    }
  }

  statement {
    sid    = "AllowCloudTrailGenerateDataKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${var.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "AllowCloudTrailDescribeKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = var.allow_aws_config ? [1] : []
    content {
      sid    = "AllowAwsConfigDelivery"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
      actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.prefix} customer managed key (logs, CloudTrail, EKS secrets, bastion/VPN disks)"
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.key.json
  tags                    = merge(var.tags, { Name = "${var.prefix}-cmk" })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.prefix}"
  target_key_id = aws_kms_key.this.key_id
}

output "key_arn" { value = aws_kms_key.this.arn }
output "key_id" { value = aws_kms_key.this.key_id }
