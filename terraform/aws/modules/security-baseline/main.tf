# Two halves, each managed by one environment: the account-wide settings (manage_account: S3 account public-access
# block, IAM password policy, multi-region CloudTrail) and the settings of this region (manage_region: GuardDuty, IAM
# Access Analyzer, Security Hub, AWS Config). EBS encryption by default is regional too; it is switched on whenever this
# module exists (enabling it is idempotent), so a region never depends on the account half. `cloudseed destroy` only
# forgets it (KEEP_ON_DESTROY in cloudseed/clouds/aws.py), but an apply that removes the module (both halves switched
# off) deletes the resource, which turns the setting OFF for the whole region.
data "aws_partition" "current" {}

locals {
  partition       = data.aws_partition.current.partition
  cloudtrail      = var.manage_account && var.enable_cloudtrail
  guardduty       = var.manage_region && var.enable_guardduty
  access_analyzer = var.manage_region && var.enable_access_analyzer
  security_hub    = var.manage_region && var.enable_security_hub
  aws_config      = var.manage_region && var.enable_aws_config
  # the log bucket receives CloudTrail logs and AWS Config snapshots: created for either
  log_bucket = local.cloudtrail || local.aws_config
}

# ---- Account-wide guard rails ----
# (count added when the baseline was split in two: Terraform moves an existing object to [0] by itself)
resource "aws_s3_account_public_access_block" "this" {
  count = var.manage_account ? 1 : 0

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# New volumes are encrypted with the AWS-managed aws/ebs key. The region-wide default key is deliberately NOT pointed at
# this environment's CMK: Auto Scaling / EKS node groups, Karpenter and the EBS CSI driver have no grant on it (launches
# and PVCs fail), and every other volume in the region would depend on a key `cs destroy` schedules for deletion.
# The bastion and VPN disks name the CMK explicitly.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_iam_account_password_policy" "this" {
  count = var.manage_account ? 1 : 0

  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# An account allows ONE account-level analyzer per region (not adjustable): set enable_access_analyzer = false where one
# already exists (created in the console, or by another environment's regional baseline).
resource "aws_accessanalyzer_analyzer" "this" {
  count = local.access_analyzer ? 1 : 0

  analyzer_name = "${var.prefix}-access-analyzer"
  type          = "ACCOUNT"
  tags          = var.tags
}

resource "aws_guardduty_detector" "this" {
  count = local.guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.tags
}

# ---- CloudTrail ----
locals {
  trail_name  = "${var.prefix}-trail"
  trail_arn   = "arn:${local.partition}:cloudtrail:${var.region}:${var.account_id}:trail/${local.trail_name}"
  bucket_name = "${lower(var.prefix)}-cloudtrail-${var.account_id}"
}

resource "aws_s3_bucket" "trail" {
  count = local.log_bucket ? 1 : 0

  bucket        = local.bucket_name
  force_destroy = true
  tags          = merge(var.tags, { Name = local.bucket_name })
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  count  = local.log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count  = local.log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  count  = local.log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  count  = local.log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  count  = local.log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id

  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  count = local.log_bucket ? 1 : 0

  dynamic "statement" {
    for_each = local.cloudtrail ? [1] : []
    content {
      sid    = "AWSCloudTrailAclCheck"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      actions   = ["s3:GetBucketAcl"]
      resources = [aws_s3_bucket.trail[0].arn]
      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = [local.trail_arn]
      }
    }
  }

  dynamic "statement" {
    for_each = local.cloudtrail ? [1] : []
    content {
      sid    = "AWSCloudTrailWrite"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      actions   = ["s3:PutObject"]
      resources = ["${aws_s3_bucket.trail[0].arn}/AWSLogs/${var.account_id}/*"]
      condition {
        test     = "StringEquals"
        variable = "s3:x-amz-acl"
        values   = ["bucket-owner-full-control"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = [local.trail_arn]
      }
    }
  }

  # AWS Config (service-linked role) delivers snapshots and history under config/ in the same bucket.
  dynamic "statement" {
    for_each = local.aws_config ? { AWSConfigBucketPermissionsCheck = "s3:GetBucketAcl", AWSConfigBucketExistenceCheck = "s3:ListBucket" } : {}
    content {
      sid    = statement.key
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
      actions   = [statement.value]
      resources = [aws_s3_bucket.trail[0].arn]
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = local.aws_config ? [1] : []
    content {
      sid    = "AWSConfigBucketDelivery"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
      actions   = ["s3:PutObject"]
      resources = ["${aws_s3_bucket.trail[0].arn}/${local.config_prefix}/AWSLogs/${var.account_id}/Config/*"]
      condition {
        test     = "StringEquals"
        variable = "s3:x-amz-acl"
        values   = ["bucket-owner-full-control"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail[0].arn, "${aws_s3_bucket.trail[0].arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  count  = local.log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  policy = data.aws_iam_policy_document.trail_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudwatch_log_group" "trail" {
  count = local.cloudtrail ? 1 : 0

  name              = "/cloudseed/${var.prefix}/cloudtrail"
  retention_in_days = min(var.log_retention_days, 3653)
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "trail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail" {
  count = local.cloudtrail ? 1 : 0

  name               = "${var.prefix}-cloudtrail-logs"
  assume_role_policy = data.aws_iam_policy_document.trail_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "trail_logs" {
  count = local.cloudtrail ? 1 : 0

  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail[0].arn}:*"]
  }
}

resource "aws_iam_role_policy" "trail" {
  count = local.cloudtrail ? 1 : 0

  name   = "cloudtrail-to-cloudwatch"
  role   = aws_iam_role.trail[0].id
  policy = data.aws_iam_policy_document.trail_logs[0].json
}

resource "aws_cloudtrail" "this" {
  count = local.cloudtrail ? 1 : 0

  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true
  kms_key_id                    = var.kms_key_arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail[0].arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail[0].arn
  tags                          = merge(var.tags, { Name = local.trail_name })

  depends_on = [aws_s3_bucket_policy.trail, aws_iam_role_policy.trail]
}

# ---- AWS Config (on with Security Hub unless enable_aws_config = false; part of the regional half) ----
# Most Security Hub (FSBP) controls are AWS Config rules: without a recorder they never evaluate and Config.1 fails.
# It delivers to the log bucket above (created for it when this environment has no CloudTrail).
# One recorder per region: set enable_aws_config = false where Config already records (Control Tower, Organizations).
# The service-linked role is account-wide and often exists already; cloudseed adopts it and never deletes it.
locals {
  config_prefix = "config"
}

resource "aws_iam_service_linked_role" "config" {
  count            = local.aws_config ? 1 : 0
  aws_service_name = "config.amazonaws.com"
}

resource "aws_config_configuration_recorder" "this" {
  count    = local.aws_config ? 1 : 0
  name     = "${var.prefix}-config"
  role_arn = aws_iam_service_linked_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = local.aws_config ? 1 : 0
  name           = "${var.prefix}-config"
  s3_bucket_name = aws_s3_bucket.trail[0].id
  s3_key_prefix  = local.config_prefix
  s3_kms_key_arn = var.kms_key_arn

  depends_on = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.trail]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = local.aws_config ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# ---- Security Hub (optional) ----
resource "aws_securityhub_account" "this" {
  count = local.security_hub ? 1 : 0

  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count = local.security_hub ? 1 : 0

  standards_arn = "arn:${local.partition}:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this, aws_config_configuration_recorder_status.this]
}

output "cloudtrail_bucket" { value = try(aws_s3_bucket.trail[0].id, null) }
output "guardduty_detector_id" { value = try(aws_guardduty_detector.this[0].id, null) }
