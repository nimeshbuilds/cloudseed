variable "prefix" { type = string }
variable "vpc_cidr" { type = string }
variable "azs" { type = list(string) }
variable "subnet_newbits" { type = number }
variable "subnet_stride" {
  description = "AZ count of the original subnet layout (null = length(azs)); AZs beyond it are appended."
  type        = number
  default     = null
}
variable "single_nat_gateway" { type = bool }
variable "create_data_subnets" { type = bool }
variable "enable_flow_logs" { type = bool }
variable "flow_log_retention_days" { type = number }
variable "kms_key_arn" { type = string }
variable "tags" { type = map(string) }
