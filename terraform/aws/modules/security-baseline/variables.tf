variable "prefix" { type = string }
variable "account_id" { type = string }
variable "region" { type = string }
variable "kms_key_arn" { type = string }
variable "manage_account" {
  description = "Account-wide settings (one environment per AWS account): S3 account public-access block, IAM password policy, multi-region CloudTrail."
  type        = bool
}
variable "manage_region" {
  description = "Settings of this region (one environment per account and region): GuardDuty, IAM Access Analyzer, Security Hub, AWS Config."
  type        = bool
}
variable "enable_cloudtrail" { type = bool }
variable "enable_guardduty" { type = bool }
variable "enable_access_analyzer" { type = bool }
variable "enable_security_hub" { type = bool }
variable "enable_aws_config" { type = bool }
variable "log_retention_days" { type = number }
variable "tags" { type = map(string) }
