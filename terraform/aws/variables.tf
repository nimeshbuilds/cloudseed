variable "name" {
  description = "Base name used as a prefix for every resource."
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod...)."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
  validation {
    # AWS VPCs are /16-/28 and every subnet (vpc prefix + subnet_newbits) must be /28 or larger
    condition     = can(cidrnetmask(var.vpc_cidr)) && try(tonumber(split("/", var.vpc_cidr)[1]) >= 16 && tonumber(split("/", var.vpc_cidr)[1]) + var.subnet_newbits <= 28, false)
    error_message = "vpc_cidr must be an IPv4 network between /16 and /(28 - subnet_newbits), e.g. 10.0.0.0/16."
  }
}

variable "az_count" {
  description = "Number of availability zones to spread subnets across."
  type        = number
  default     = 2
  validation {
    condition     = var.az_count >= 1 && var.az_count <= 5 && floor(var.az_count) == var.az_count
    error_message = "az_count must be a whole number between 1 and 5."
  }
}

variable "subnet_newbits" {
  description = "Extra bits added to vpc_cidr to carve subnets (4 => /20s from a /16; at most 12, as AWS's smallest subnet is a /28)."
  type        = number
  default     = 4
  validation {
    condition     = var.subnet_newbits >= 1 && var.subnet_newbits <= 12 && floor(var.subnet_newbits) == var.subnet_newbits
    error_message = "subnet_newbits must be a whole number between 1 and 12 (a /16 VPC with 12 gives /28 subnets, AWS's smallest)."
  }
}

variable "subnet_stride" {
  description = "Subnet layout: the az_count the environment was first deployed with (null = az_count). The first subnet_stride AZs get subnet blocks public 0.., private stride.., data 2*stride..; AZs added later get three blocks each after those, so changing az_count never re-addresses an existing subnet. cloudseed pins it at the first setup."
  type        = number
  default     = null
  validation {
    condition     = var.subnet_stride == null ? true : (var.subnet_stride >= 1 && var.subnet_stride <= 5 && floor(var.subnet_stride) == var.subnet_stride)
    error_message = "subnet_stride must be a whole number between 1 and 5 (or null)."
  }
}

variable "single_nat_gateway" {
  description = "Use one NAT gateway for all private subnets (cheaper) instead of one per AZ (more resilient)."
  type        = bool
  default     = true
}

variable "create_data_subnets" {
  description = "Create an isolated data tier (no internet route at all)."
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Send VPC flow logs to an encrypted CloudWatch log group."
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Retention (days) for VPC flow logs; one of the values CloudWatch Logs accepts (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653; 0 = never expire)."
  type        = number
  default     = 30
  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.flow_log_retention_days)
    error_message = "flow_log_retention_days must be a CloudWatch Logs retention: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288 or 3653 (0 = never expire)."
  }
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to SSH to the bastion. Usually just your public IP as /32."
  type        = list(string)
  validation {
    condition     = length(var.allowed_ssh_cidrs) > 0 && !contains(var.allowed_ssh_cidrs, "0.0.0.0/0")
    error_message = "allowed_ssh_cidrs must be non-empty and must never contain 0.0.0.0/0."
  }
  validation {
    condition     = alltrue([for c in var.allowed_ssh_cidrs : can(cidrnetmask(c)) && try(tonumber(split("/", c)[1]) >= 8, false)])
    error_message = "allowed_ssh_cidrs must be IPv4 CIDRs (the bastion has no IPv6 address) no wider than /8."
  }
}

variable "ssh_public_key" {
  description = "OpenSSH public key installed on the bastion."
  type        = string
}

variable "bastion_instance_type" {
  description = "Instance type for the bastion (e.g. t3.micro, t4g.micro)."
  type        = string
  default     = "t3.micro"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*\\.[a-z0-9][a-z0-9-]*$", var.bastion_instance_type))
    error_message = "bastion_instance_type must be an EC2 instance type such as t3.micro."
  }
}

variable "bastion_root_volume_size" {
  description = "Root volume size (GiB) for the bastion; at least 8 (the Amazon Linux 2023 image)."
  type        = number
  default     = 10
  validation {
    condition     = var.bastion_root_volume_size >= 8 && var.bastion_root_volume_size <= 16384 && floor(var.bastion_root_volume_size) == var.bastion_root_volume_size
    error_message = "bastion_root_volume_size must be a whole number of GiB from 8 (the Amazon Linux 2023 image) to 16384."
  }
}

variable "enable_account_baseline" {
  description = "Manage the account-wide security settings: S3 account public-access block, IAM password policy, multi-region CloudTrail (EBS encryption by default is switched on in this region with it). Enable in only ONE environment per AWS account."
  type        = bool
  default     = true
}

variable "enable_regional_baseline" {
  description = "Manage this region's security settings: EBS encryption by default, GuardDuty, IAM Access Analyzer, Security Hub/AWS Config when enabled. Enable in ONE environment per AWS account AND region (a second environment in another region keeps it on). null = same as enable_account_baseline."
  type        = bool
  default     = null
}

variable "enable_cloudtrail" {
  description = "Create a multi-region, KMS-encrypted CloudTrail with log validation."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty threat detection in this region (regional baseline). A detector that already exists is never adopted, so this environment's destroy never switches it off: set false to leave it alone. cloudseed setup and apply look for one before changing anything (with the aws CLI installed; otherwise the apply stops at it): while this is only on by default they leave it alone and save enable_guardduty=false; set true explicitly, they stop and name this variable."
  type        = bool
  default     = true
}

variable "enable_access_analyzer" {
  description = "Create an account-level IAM Access Analyzer in this region (regional baseline). AWS allows only one per account and region (not adjustable): set false when one already exists."
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub with the AWS Foundational Security Best Practices standard in this region (part of the regional baseline). Its controls need AWS Config recording, which is turned on with it (see enable_aws_config)."
  type        = bool
  default     = false
}

variable "enable_aws_config" {
  description = "Record resource configurations with AWS Config (regional baseline; delivered to the baseline's log bucket; billed per recorded item). null = on together with enable_security_hub. Set false when Config already records in this region (Control Tower, Organizations): a region holds only one recorder."
  type        = bool
  default     = null
}

variable "log_retention_days" {
  description = "Retention (days) for CloudTrail logs (S3 lifecycle), EKS control-plane logs and the CloudTrail log group. CloudWatch keeps at most 3653 days; up to that, use a value CloudWatch Logs accepts (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653)."
  type        = number
  default     = 365
  validation {
    condition     = floor(var.log_retention_days) == var.log_retention_days && (var.log_retention_days >= 3653 || contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288], var.log_retention_days))
    error_message = "log_retention_days must be a CloudWatch Logs retention (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288) or 3653 and more (the S3 copy then keeps it longer; CloudWatch stops at 3653)."
  }
}

variable "kms_deletion_window_in_days" {
  description = "Waiting period (7-30 days) before a destroyed KMS key is actually deleted."
  type        = number
  default     = 7
  validation {
    condition     = var.kms_deletion_window_in_days >= 7 && var.kms_deletion_window_in_days <= 30 && floor(var.kms_deletion_window_in_days) == var.kms_deletion_window_in_days
    error_message = "kms_deletion_window_in_days must be a whole number of days from 7 to 30 (the range KMS accepts)."
  }
}

variable "tags" {
  description = "Extra tags applied to every resource. An Environment tag here replaces the default (Environment = environment); ManagedBy is always cloudseed."
  type        = map(string)
  default     = {}
}

# ---------- Kubernetes (EKS) ----------
variable "enable_kubernetes" {
  description = "Create a private EKS cluster in the private subnets."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_kubernetes || var.az_count >= 2
    error_message = "EKS needs subnets in at least two availability zones: set az_count to 2 or more (it is ${var.az_count})."
  }
}

variable "kubernetes_version" {
  description = "EKS Kubernetes version as MAJOR.MINOR, e.g. 1.33 (null = EKS's current default). EKS refuses versions it no longer supports."
  type        = string
  default     = null
  validation {
    condition     = var.kubernetes_version == null ? true : can(regex("^1\\.[0-9]+$", var.kubernetes_version))
    error_message = "kubernetes_version must be MAJOR.MINOR such as 1.33 (no leading v, no patch version)."
  }
}

variable "kubernetes_node_size" {
  description = "Instance type of the EKS worker nodes (Graviton types such as t4g/m7g get the arm64 image)."
  type        = string
  default     = "t3.medium"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*\\.[a-z0-9][a-z0-9-]*$", var.kubernetes_node_size))
    error_message = "kubernetes_node_size must be an EC2 instance type such as t3.medium."
  }
}

variable "kubernetes_node_count" {
  description = "Initial number of EKS worker nodes (at least 1: CoreDNS and the EBS CSI driver need a node), between kubernetes_node_min and kubernetes_node_max."
  type        = number
  default     = 2
  validation {
    condition     = !var.enable_kubernetes || (var.kubernetes_node_count >= var.kubernetes_node_min && var.kubernetes_node_count <= var.kubernetes_node_max)
    error_message = "kubernetes_node_count = ${var.kubernetes_node_count} is outside kubernetes_node_min..kubernetes_node_max (${var.kubernetes_node_min}..${var.kubernetes_node_max}): change the count or the bounds."
  }
  validation {
    condition     = !var.enable_kubernetes || var.kubernetes_node_count >= 1
    error_message = "kubernetes_node_count must be at least 1: the CoreDNS and EBS CSI add-ons never become ready on a node group without nodes (kubernetes_node_min may still be 0)."
  }
}

variable "kubernetes_node_min" {
  description = "Smallest size of the EKS node group (the autoscaler never goes below it)."
  type        = number
  default     = 1
  validation {
    condition     = var.kubernetes_node_min >= 0 && floor(var.kubernetes_node_min) == var.kubernetes_node_min
    error_message = "kubernetes_node_min must be a whole number >= 0."
  }
}

variable "kubernetes_node_max" {
  description = "Largest size of the EKS node group."
  type        = number
  default     = 4
  validation {
    condition     = var.kubernetes_node_max >= 1 && var.kubernetes_node_max >= var.kubernetes_node_min && floor(var.kubernetes_node_max) == var.kubernetes_node_max
    error_message = "kubernetes_node_max must be a whole number >= 1 and >= kubernetes_node_min (${var.kubernetes_node_min})."
  }
}

variable "kubernetes_public_endpoint" {
  description = "Also expose the API endpoint publicly, restricted to allowed_ssh_cidrs. Default: private only (reach it via bastion/VPN)."
  type        = bool
  default     = false
}

variable "external_secrets_prefixes" {
  description = "Secrets Manager names / SSM parameter paths the external-secrets controller may read, as prefixes. null = <name>-<environment>/ (e.g. secret acme-dev/db, parameter /acme-dev/db). Use * for every secret in the account."
  type        = list(string)
  default     = null
  validation {
    condition     = var.external_secrets_prefixes == null ? true : length(var.external_secrets_prefixes) > 0
    error_message = "external_secrets_prefixes must list at least one prefix (or be null for the environment default)."
  }
}

variable "platform_prereqs" {
  description = "Cloud-side prerequisites for optional platform items (velero: S3 bucket + IAM; karpenter: node role, queue, tags). Managed by `cs platform install`."
  type        = list(string)
  default     = []
}

variable "fips_mode" {
  description = "FIPS 140 mode for the whole environment: FIPS service endpoints, FIPS node images (Bottlerocket FIPS on EKS), FIPS crypto on the bastion/VPN hosts (kernel fips=1, FIPS-only SSH algorithms), RSA-4096 SSH keys (ed25519 is not FIPS-approved; EC2/Azure refuse ECDSA)."
  type        = bool
  default     = false
}

# ---------- VPN ----------
variable "enable_vpn" {
  description = "Create a VPN host (OpenVPN or Tailscale subnet router) in the public subnet."
  type        = bool
  default     = false
}

variable "vpn_type" {
  description = "VPN flavour: openvpn (self-contained, client certificates) or tailscale (subnet router, needs TS_AUTHKEY)."
  type        = string
  default     = "openvpn"
  validation {
    condition     = contains(["openvpn", "tailscale"], var.vpn_type)
    error_message = "vpn_type must be openvpn or tailscale."
  }
}

variable "vpn_instance_type" {
  description = "Instance type of the VPN host."
  type        = string
  default     = "t3.micro"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*\\.[a-z0-9][a-z0-9-]*$", var.vpn_instance_type))
    error_message = "vpn_instance_type must be an EC2 instance type such as t3.micro."
  }
}

variable "vpn_port" {
  description = "UDP port the OpenVPN server listens on (1-65535; unused with vpn_type=tailscale, which uses 41641)."
  type        = number
  default     = 1194
  validation {
    condition     = var.vpn_port >= 1 && var.vpn_port <= 65535 && floor(var.vpn_port) == var.vpn_port
    error_message = "vpn_port must be a whole number between 1 and 65535."
  }
}
