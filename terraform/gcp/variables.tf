variable "project_id" {
  description = "GCP project to deploy into."
  type        = string
}

variable "region" {
  description = "Region of the network, NAT and regional resources."
  type        = string
}

variable "zone" {
  description = "Zone (inside region) for the bastion, the VPN host and the zonal GKE cluster."
  type        = string
  validation {
    # the subnet lives in var.region; the bastion, VPN host and GKE cluster in var.zone
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+-[a-z]$", var.zone)) && startswith(var.zone, "${var.region}-")
    error_message = "zone must be a zone of the chosen region, e.g. us-central1-a for region us-central1."
  }
}

variable "name" {
  description = "Base name used as a prefix for every resource."
  type        = string
}

variable "environment" {
  description = "Environment name (dev, prod, ...): the second half of every resource name and the environment label."
  type        = string
}

variable "network_cidr" {
  description = "Address space carved into the public and private subnets (with subnet_newbits = 4: the first and second /20 of a /16)."
  type        = string
  default     = "10.10.0.0/16"
}

variable "subnet_newbits" {
  description = "Extra bits added to network_cidr to carve the public and private subnets (4 => /20s from a /16)."
  type        = number
  default     = 4
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to SSH to the bastion."
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
  description = "OpenSSH public key for the bastion and VPN host (the environment's generated key, or --ssh-public-key)."
  type        = string
}

variable "ssh_username" {
  description = "Login user on the bastion and VPN host (metadata SSH key). With enable_os_login cloudseed passes your Google account's OS Login POSIX username instead."
  type        = string
  default     = "cloudseed"
}

variable "enable_os_login" {
  description = "Use OS Login (IAM-managed SSH) on the bastion and VPN host instead of a metadata key. cloudseed registers the environment's key with your Google account through gcloud and grants that account OS Admin Login on both."
  type        = bool
  default     = false
}

variable "os_login_member" {
  description = "IAM member granted OS Admin Login on the bastion and VPN host (and actAs on their service accounts) when enable_os_login is on. Set by cloudseed from your gcloud account."
  type        = string
  default     = ""
}

variable "bastion_machine_type" {
  description = "Machine type of the bastion (a name such as e2-micro or e2-small)."
  type        = string
  default     = "e2-micro"
  validation {
    condition     = can(regex("^[a-z0-9]+(-[a-z0-9]+)+$", var.bastion_machine_type))
    error_message = "bastion_machine_type must be a Compute Engine machine type in lower case, e.g. e2-micro or e2-small."
  }
}

variable "bastion_image" {
  description = "Boot image of the bastion (project/family such as debian-cloud/debian-12, or project/image). With fips_mode = true it is replaced by Ubuntu Pro FIPS 22.04 while left at this default."
  type        = string
  default     = "debian-cloud/debian-12"
  validation {
    condition     = trimspace(var.bastion_image) != ""
    error_message = "bastion_image cannot be empty (e.g. debian-cloud/debian-12)."
  }
}

variable "bastion_disk_size" {
  description = "Boot disk size of the bastion in GB (at least 10: the image size)."
  type        = number
  default     = 10
  validation {
    condition     = var.bastion_disk_size == floor(var.bastion_disk_size) && var.bastion_disk_size >= 10 && var.bastion_disk_size <= 65536
    error_message = "bastion_disk_size must be a whole number of GB from 10 to 65536."
  }
}

variable "enable_apis" {
  description = "Enable the required Google APIs on the project."
  type        = bool
  default     = true
}

variable "enable_project_baseline" {
  description = "Manage the project-wide logging settings (the _Default log bucket's retention and, with enable_data_access_audit_logs, the allServices audit config) from this environment. Set false for a second environment in the same project. A destroy leaves both settings in place; switching this off on an environment that set them removes the audit config (unless `cloudseed destroy --target module.stack.module.security_baseline` first drops it from the state) and leaves the retention as it is."
  type        = bool
  default     = true
}

variable "enable_data_access_audit_logs" {
  description = "Turn on Data Access audit logs for all services (extra logging cost). Project-wide; needs enable_project_baseline."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention for the project's _Default log bucket (1-3650 days). Project-wide; needs enable_project_baseline."
  type        = number
  default     = 90
  validation {
    condition     = var.log_retention_days == floor(var.log_retention_days) && var.log_retention_days >= 1 && var.log_retention_days <= 3650
    error_message = "log_retention_days must be a whole number of days from 1 to 3650."
  }
}

variable "labels" {
  description = "Labels on every resource (set by cloudseed from --tag and the built-in project/environment/owner/managedby/cloudseedenv labels)."
  type        = map(string)
  default     = {}
}

# ---------- Kubernetes (GKE) ----------
variable "enable_kubernetes" {
  description = "Create a private GKE cluster in the private subnet."
  type        = bool
  default     = false
}

variable "kubernetes_version" {
  description = "GKE minimum master version (null = release channel default)."
  type        = string
  default     = null
}

variable "kubernetes_node_size" {
  description = "Kubernetes node size: the machine type of the GKE nodes (a name such as e2-standard-2)."
  type        = string
  default     = "e2-standard-2"
  validation {
    condition     = can(regex("^[a-z0-9]+(-[a-z0-9]+)+$", var.kubernetes_node_size))
    error_message = "kubernetes_node_size must be a Compute Engine machine type in lower case, e.g. e2-standard-2."
  }
}

variable "kubernetes_node_count" {
  description = "Nodes in the GKE node pool, and the pool's autoscaling floor (what `cloudseed node add|remove|scale` changes)."
  type        = number
  default     = 2
  validation {
    # checked only with a cluster: an unused value must not block a plan or a destroy
    condition     = !var.enable_kubernetes || (var.kubernetes_node_count == floor(var.kubernetes_node_count) && var.kubernetes_node_count >= 1)
    error_message = "kubernetes_node_count must be a whole number, 1 or more (a node pool needs at least 1 node)."
  }
}

variable "kubernetes_node_min" {
  description = "Autoscaler minimum of the GKE node pool; the pool never scales below kubernetes_node_count (floor = max(kubernetes_node_min, kubernetes_node_count))."
  type        = number
  default     = 1
  validation {
    condition     = var.kubernetes_node_min == floor(var.kubernetes_node_min) && var.kubernetes_node_min >= 0
    error_message = "kubernetes_node_min must be a whole number, 0 or more."
  }
}

variable "kubernetes_node_max" {
  description = "Autoscaler maximum of the GKE node pool (raised to kubernetes_node_count / kubernetes_node_min when lower)."
  type        = number
  default     = 4
  validation {
    condition     = var.kubernetes_node_max == floor(var.kubernetes_node_max) && var.kubernetes_node_max >= 1
    error_message = "kubernetes_node_max must be a whole number, 1 or more."
  }
}

variable "kubernetes_public_endpoint" {
  description = "Also expose the control plane publicly, restricted to allowed_ssh_cidrs. Default: private endpoint only."
  type        = bool
  default     = false
}

variable "kubernetes_master_cidr" {
  description = "/28 for the GKE control plane; must not overlap network_cidr (cloudseed picks a free one when the default would)."
  type        = string
  default     = "172.16.0.0/28"
}

# ---------- VPN ----------
variable "enable_vpn" {
  description = "Create a VPN host (OpenVPN or a Tailscale subnet router) in the public subnet for private-network access."
  type        = bool
  default     = false
}

variable "vpn_type" {
  description = "VPN on the VPN host: openvpn (self-contained, client certificates) or tailscale (subnet router, needs TS_AUTHKEY)."
  type        = string
  default     = "openvpn"
  validation {
    condition     = contains(["openvpn", "tailscale"], var.vpn_type)
    error_message = "vpn_type must be openvpn or tailscale."
  }
}

variable "vpn_machine_type" {
  description = "Machine type of the VPN host (a name such as e2-micro)."
  type        = string
  default     = "e2-micro"
  validation {
    condition     = can(regex("^[a-z0-9]+(-[a-z0-9]+)+$", var.vpn_machine_type))
    error_message = "vpn_machine_type must be a Compute Engine machine type in lower case, e.g. e2-micro."
  }
}

variable "vpn_port" {
  description = "UDP port the OpenVPN server listens on (unused with vpn_type = tailscale: a Tailscale VPN host uses 41641)."
  type        = number
  default     = 1194
  validation {
    condition     = var.vpn_port == floor(var.vpn_port) && var.vpn_port >= 1 && var.vpn_port <= 65535
    error_message = "vpn_port must be a whole number from 1 to 65535."
  }
}

variable "platform_prereqs" {
  description = "Cloud-side prerequisites for optional platform items (velero: GCS bucket + Workload Identity service account scoped to it). Managed by `cs platform install`."
  type        = list(string)
  default     = []
}

variable "fips_mode" {
  description = "FIPS 140 mode for the whole environment: Ubuntu Pro FIPS bastion (unless bastion_image is set) and VPN images, COS nodes on GKE (FIPS-validated kernel crypto), FIPS-only SSH algorithms, ECDSA SSH keys."
  type        = bool
  default     = false
}
