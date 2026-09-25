variable "name" {
  description = "Base name used as a prefix for every VM."
  type        = string
}

variable "environment" {
  type = string
}

variable "private_cidr" {
  description = "Host-only private network behind the bastion (workloads live here, no direct internet)."
  type        = string
  default     = "10.100.0.0/24"
}

variable "base_disk" {
  description = "Path to the base cloud-image VMDK (downloaded/converted by cloudseed for this host's architecture)."
  type        = string
}

variable "guest_os_id" {
  description = "VMware guestOS id matching the image and host architecture (ubuntu-64 or arm-ubuntu-64)."
  type        = string
}

variable "vm_dir" {
  description = "Directory holding the VMs."
  type        = string
}

variable "ssh_public_key" {
  type = string
}

variable "ssh_username" {
  description = "Login user cloud-init creates at first boot on every VM. Changing it on a deployed environment rebuilds every VM (their disks are wiped)."
  type        = string
  default     = "cloudseed"
}

variable "bastion_cpus" {
  type    = number
  default = 2
  validation {
    condition     = floor(var.bastion_cpus) == var.bastion_cpus && var.bastion_cpus >= 1
    error_message = "bastion_cpus must be a whole number of vCPUs, at least 1."
  }
}

variable "bastion_memory_mb" {
  type    = number
  default = 2048
  validation {
    condition     = floor(var.bastion_memory_mb) == var.bastion_memory_mb && var.bastion_memory_mb >= 4 && var.bastion_memory_mb % 4 == 0
    error_message = "bastion_memory_mb must be a whole number of MB and a multiple of 4 (VMware's rule for VM memory)."
  }
}

variable "bastion_disk_gb" {
  type    = number
  default = 20
  validation {
    condition     = floor(var.bastion_disk_gb) == var.bastion_disk_gb && var.bastion_disk_gb >= 1
    error_message = "bastion_disk_gb must be a whole number of GB, at least 1."
  }
}

variable "workload_count" {
  description = "Private workload VMs behind the bastion (no NAT NIC; egress through the bastion)."
  type        = number
  default     = 0
  validation {
    condition     = var.workload_count >= 0 && floor(var.workload_count) == var.workload_count
    error_message = "workload_count must be a whole number, 0 or more."
  }
}

variable "workload_cpus" {
  type    = number
  default = 2
  validation {
    condition     = floor(var.workload_cpus) == var.workload_cpus && var.workload_cpus >= 1
    error_message = "workload_cpus must be a whole number of vCPUs, at least 1."
  }
}

variable "workload_memory_mb" {
  type    = number
  default = 2048
  validation {
    condition     = floor(var.workload_memory_mb) == var.workload_memory_mb && var.workload_memory_mb >= 4 && var.workload_memory_mb % 4 == 0
    error_message = "workload_memory_mb must be a whole number of MB and a multiple of 4 (VMware's rule for VM memory)."
  }
}

variable "workload_disk_gb" {
  type    = number
  default = 20
  validation {
    condition     = floor(var.workload_disk_gb) == var.workload_disk_gb && var.workload_disk_gb >= 1
    error_message = "workload_disk_gb must be a whole number of GB, at least 1."
  }
}

variable "packages" {
  description = "Extra packages cloud-init installs at first boot on the bastion and the workload VMs (Kubernetes nodes get a fixed package set). First boot only: changing it on a deployed environment rebuilds the bastion and every workload VM (their disks are wiped); to add a package to running VMs, install it over `cloudseed ssh`."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Not applied: VMware VMs have no tags (accepted so every target takes the same inputs)."
  type        = map(string)
  default     = {}
}

# ---------- Kubernetes (self-managed on VMs: RKE2 or kubeadm, installed by Ansible) ----------
variable "enable_kubernetes" {
  description = "Create control-plane and worker VMs on the private network and install Kubernetes (RKE2 or kubeadm)."
  type        = bool
  default     = false
}

variable "kubernetes_distro" {
  description = "rke2 (default; batteries included; CIS hardening profile opt-in via kubernetes_cis_profile) or kubeadm (vanilla upstream)."
  type        = string
  default     = "rke2"
  validation {
    condition     = contains(["rke2", "kubeadm"], var.kubernetes_distro)
    error_message = "kubernetes_distro must be rke2 or kubeadm."
  }
}

variable "kubernetes_control_planes" {
  description = "Control-plane VMs (1-20; an odd number keeps etcd's quorum tolerant of failures)."
  type        = number
  default     = 1
  validation {
    # only enforced with Kubernetes on: a leftover value must never block an environment without a cluster (or its destroy)
    condition     = floor(var.kubernetes_control_planes) == var.kubernetes_control_planes && (!var.enable_kubernetes || var.kubernetes_control_planes >= 1)
    error_message = "kubernetes_control_planes must be a whole number, at least 1 (a cluster needs a control plane)."
  }
}

variable "kubernetes_workers" {
  description = "Worker VMs (addresses .40 and up; at most 60 on a /24 or larger network, whose .100-.127 are kept for MetalLB's LoadBalancer pool). 0 is allowed: a cluster created without workers runs its workloads on the control planes."
  type        = number
  default     = 2
  validation {
    condition     = var.kubernetes_workers >= 0 && floor(var.kubernetes_workers) == var.kubernetes_workers
    error_message = "kubernetes_workers must be a whole number, 0 or more."
  }
}

variable "kubernetes_cpus" {
  type    = number
  default = 2
  validation {
    condition     = floor(var.kubernetes_cpus) == var.kubernetes_cpus && (!var.enable_kubernetes || var.kubernetes_cpus >= 1)
    error_message = "kubernetes_cpus must be a whole number of vCPUs, at least 1."
  }
}

variable "kubernetes_memory_mb" {
  type    = number
  default = 4096
  validation {
    condition     = floor(var.kubernetes_memory_mb) == var.kubernetes_memory_mb && (!var.enable_kubernetes || (var.kubernetes_memory_mb >= 4 && var.kubernetes_memory_mb % 4 == 0))
    error_message = "kubernetes_memory_mb must be a whole number of MB and a multiple of 4 (VMware's rule for VM memory)."
  }
}

variable "kubernetes_disk_gb" {
  type    = number
  default = 40
  validation {
    condition     = floor(var.kubernetes_disk_gb) == var.kubernetes_disk_gb && (!var.enable_kubernetes || var.kubernetes_disk_gb >= 1)
    error_message = "kubernetes_disk_gb must be a whole number of GB, at least 1."
  }
}

variable "fips_mode" {
  description = "FIPS 140 mode: Ubuntu Pro FIPS packages on every VM (needs UBUNTU_PRO_TOKEN), RKE2 (FIPS-validated Go crypto) for Kubernetes, FIPS-only SSH algorithms, ECDSA SSH keys."
  type        = bool
  default     = false
}
