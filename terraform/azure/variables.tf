variable "location" {
  type = string
}

variable "name" {
  description = "Base name used as a prefix for every resource."
  type        = string
}

variable "environment" {
  type = string
}

variable "network_cidr" {
  description = "VNet address space (public = first subnet, private = second)."
  type        = string
  default     = "10.20.0.0/16"
}

variable "subnet_newbits" {
  description = "Extra bits added to network_cidr to carve the public and private subnets (8 => /24s from a /16)."
  type        = number
  default     = 8
}

variable "allowed_ssh_cidrs" {
  type = list(string)
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
  type = string
}

variable "admin_username" {
  description = "Login user on the bastion and VPN host."
  type        = string
  default     = "azureuser"
  validation {
    # names Azure refuses for a Linux VM's admin user (the VM would only fail at create time)
    condition = !contains([
      "administrator", "admin", "user", "user1", "test", "user2", "test1", "user3", "admin1", "1", "123", "a",
      "actuser", "adm", "admin2", "aspnet", "backup", "console", "david", "guest", "john", "owner", "root", "server",
      "sql", "support", "support_388945a0", "sys", "test2", "test3", "user4", "user5",
    ], lower(var.admin_username)) && can(regex("^[A-Za-z_][A-Za-z0-9_.-]{0,31}$", var.admin_username))
    error_message = "admin_username must be 1-32 letters, digits, '_', '.' or '-' starting with a letter or '_', and not a name Azure reserves (admin, administrator, root, user, test, guest, ...)."
  }
}

variable "bastion_vm_size" {
  type    = string
  default = "Standard_B1s"
}

variable "enable_activity_log" {
  description = "Stream the subscription Activity Log to a Log Analytics workspace."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Retention of the Log Analytics workspace, in days (Azure allows up to 730; values below 30 are raised to 30)."
  type        = number
  default     = 30
  validation {
    condition     = var.log_retention_days == floor(var.log_retention_days) && var.log_retention_days >= 1 && var.log_retention_days <= 730
    error_message = "log_retention_days must be a whole number of days from 1 to 730 (Log Analytics keeps at most 730; values below 30 are raised to 30)."
  }
}

variable "enable_defender" {
  description = "Enable Microsoft Defender for Cloud (Servers + Storage) on the subscription. Paid."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}

# ---------- Kubernetes (AKS) ----------
variable "enable_kubernetes" {
  description = "Create a private AKS cluster in the private subnet."
  type        = bool
  default     = false
}

variable "kubernetes_version" {
  description = "AKS version (null = current default)."
  type        = string
  default     = null
}

variable "kubernetes_node_size" {
  type    = string
  default = "Standard_B2s"
}

variable "kubernetes_node_count" {
  description = "Nodes the AKS system pool starts with (at least kubernetes_node_min; kubernetes_node_max is raised to it when lower); afterwards the cluster autoscaler owns the count."
  type        = number
  default     = 2
  validation {
    condition     = var.kubernetes_node_count >= 1 && floor(var.kubernetes_node_count) == var.kubernetes_node_count
    error_message = "kubernetes_node_count must be a whole number >= 1."
  }
}

variable "kubernetes_node_min" {
  description = "Autoscaler minimum of the AKS system pool (the autoscaler adds nodes up to it)."
  type        = number
  default     = 1
  validation {
    condition     = var.kubernetes_node_min >= 1 && floor(var.kubernetes_node_min) == var.kubernetes_node_min
    error_message = "kubernetes_node_min must be a whole number >= 1 (the AKS system pool cannot scale to zero)."
  }
}

variable "kubernetes_node_max" {
  description = "Autoscaler maximum of the AKS system pool."
  type        = number
  default     = 4
  validation {
    condition     = floor(var.kubernetes_node_max) == var.kubernetes_node_max && var.kubernetes_node_max >= var.kubernetes_node_min
    error_message = "kubernetes_node_max must be a whole number >= kubernetes_node_min."
  }
}

variable "kubernetes_public_endpoint" {
  description = "Public API server restricted to allowed_ssh_cidrs (plus the environment's NAT egress IP and the bastion, which the nodes and tunnels use) instead of a private cluster. Changing it later re-creates the cluster."
  type        = bool
  default     = false
}

# ---------- VPN ----------
variable "enable_vpn" {
  description = "Create a VPN host in the public subnet for access to the private network."
  type        = bool
  default     = false
}

variable "vpn_type" {
  description = "VPN flavour on the VPN host: openvpn (self-contained, client certificates) or tailscale (subnet router, needs TS_AUTHKEY)."
  type        = string
  default     = "openvpn"
  validation {
    condition     = contains(["openvpn", "tailscale"], var.vpn_type)
    error_message = "vpn_type must be openvpn or tailscale."
  }
}

variable "vpn_vm_size" {
  description = "VM size of the VPN host."
  type        = string
  default     = "Standard_B1s"
}

variable "vpn_port" {
  description = "UDP port the OpenVPN server listens on (a Tailscale VPN host uses 41641)."
  type        = number
  default     = 1194
  validation {
    condition     = var.vpn_port >= 1 && var.vpn_port <= 65535 && floor(var.vpn_port) == var.vpn_port
    error_message = "vpn_port must be a whole number between 1 and 65535."
  }
}

variable "platform_prereqs" {
  description = "Cloud-side prerequisites for optional platform items (velero: storage account + container + workload identity + snapshot role). Managed by `cs platform install`."
  type        = list(string)
  default     = []
}

variable "fips_mode" {
  description = "FIPS 140 mode for the whole environment: Ubuntu Pro FIPS bastion/VPN images (marketplace terms accepted automatically), FIPS-enabled AKS node pool, FIPS-only SSH algorithms, ECDSA SSH keys."
  type        = bool
  default     = false
}

variable "kubernetes_sku_tier" {
  description = "AKS control-plane tier: Free or Standard (paid uptime SLA)."
  type        = string
  default     = "Free"
  validation {
    condition     = contains(["Free", "Standard"], var.kubernetes_sku_tier)
    error_message = "kubernetes_sku_tier must be Free or Standard."
  }
}

variable "kubernetes_zones" {
  description = "AKS system-pool availability zones. Confirm support in the selected region and VM size; changing zones rotates nodes."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for z in var.kubernetes_zones : contains(["1", "2", "3"], z)]) && length(distinct(var.kubernetes_zones)) == length(var.kubernetes_zones)
    error_message = "kubernetes_zones must contain distinct Azure availability zone strings: 1, 2, 3."
  }
}
