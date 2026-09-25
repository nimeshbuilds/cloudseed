# VPN host (OpenVPN or Tailscale subnet router) in the public subnet, configured by Ansible.
variable "project_id" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "prefix" { type = string }
variable "firewall_prefix" {
  description = "Prefix for firewall-rule names (63-character limit); computed by the names module."
  type        = string
}
variable "account_id" {
  description = "Service-account ID (6-30 characters, unique in the project); computed by the names module."
  type        = string
}
variable "network_name" { type = string }
variable "subnetwork_id" { type = string }
variable "private_tag" { type = string }
variable "vpn_type" { type = string }
variable "vpn_port" { type = number }
variable "allowed_ssh_cidrs" { type = list(string) }
variable "machine_type" { type = string }
variable "fips_mode" {
  description = "FIPS 140 mode: boot the Ubuntu Pro FIPS image (FIPS-validated modules active at first boot, no token needed)."
  type        = bool
  default     = false
}
variable "ssh_public_key" { type = string }
variable "ssh_username" { type = string }
variable "enable_os_login" {
  description = "OS Login (IAM-managed SSH) instead of a metadata key, as on the bastion."
  type        = bool
  default     = false
}
variable "os_login_member" {
  description = "IAM member (user:... or serviceAccount:...) that logs in through OS Login; granted OS Admin Login on the VPN host and actAs on its service account. Empty: no grant."
  type        = string
  default     = ""
}
variable "labels" { type = map(string) }

locals {
  tag = "${var.prefix}-vpn"
  # same Ubuntu Pro FIPS 22.04 image as the FIPS bastion: boots with fips_enabled=1, so the fips role has nothing to attach
  image = var.fips_mode ? "ubuntu-os-pro-cloud/ubuntu-pro-fips-2204-lts" : "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
}

resource "google_service_account" "vpn" {
  project      = var.project_id
  account_id   = var.account_id
  display_name = "${var.prefix} vpn"
}

resource "google_project_iam_member" "vpn_logs" {
  for_each = toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.vpn.email}"
}

resource "google_compute_firewall" "vpn_port" {
  project       = var.project_id
  name          = "${var.firewall_prefix}-allow-vpn"
  network       = var.network_name
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.tag]

  allow {
    protocol = "udp"
    ports    = [var.vpn_type == "openvpn" ? tostring(var.vpn_port) : "41641"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "vpn_ssh" {
  project       = var.project_id
  name          = "${var.firewall_prefix}-allow-ssh-to-vpn"
  network       = var.network_name
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = var.allowed_ssh_cidrs
  source_tags   = ["${var.prefix}-bastion"]
  target_tags   = [local.tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# VPN clients (NATed behind the host) may reach private workloads.
resource "google_compute_firewall" "private_from_vpn" {
  project     = var.project_id
  name        = "${var.firewall_prefix}-allow-private-from-vpn"
  network     = var.network_name
  direction   = "INGRESS"
  priority    = 1000
  source_tags = [local.tag]
  target_tags = [var.private_tag]

  allow {
    protocol = "all"
  }
}

resource "google_compute_address" "vpn" {
  project = var.project_id
  name    = "${var.prefix}-vpn"
  region  = var.region
}

resource "google_compute_instance" "vpn" {
  project        = var.project_id
  name           = "${var.prefix}-vpn"
  zone           = var.zone
  machine_type   = var.machine_type
  tags           = [local.tag]
  labels         = merge(var.labels, { role = "vpn" })
  can_ip_forward = true

  boot_disk {
    initialize_params {
      image = local.image
      size  = 10
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = var.subnetwork_id
    access_config {
      nat_ip = google_compute_address.vpn.address
    }
  }

  # like the bastion: with OS Login the key lives in the user's Google profile and access is IAM (an org enforcing
  # constraints/compute.requireOsLogin refuses an instance that sets enable-oslogin=FALSE)
  metadata = merge(
    {
      enable-oslogin         = var.enable_os_login ? "TRUE" : "FALSE"
      block-project-ssh-keys = "TRUE"
    },
    var.enable_os_login ? {} : { ssh-keys = "${var.ssh_username}:${var.ssh_public_key}" }
  )

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  service_account {
    email  = google_service_account.vpn.email
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
  deletion_protection       = false
}

# OS Login: provisioning (OpenVPN / Tailscale roles) needs sudo, i.e. OS Admin Login, and a VM with an attached
# service account also needs actAs on it.
locals {
  os_login_grant = var.enable_os_login && var.os_login_member != ""
}

resource "google_compute_instance_iam_member" "os_admin_login" {
  count         = local.os_login_grant ? 1 : 0
  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.vpn.name
  role          = "roles/compute.osAdminLogin"
  member        = var.os_login_member
}

resource "google_service_account_iam_member" "os_login_act_as" {
  count              = local.os_login_grant ? 1 : 0
  service_account_id = google_service_account.vpn.name
  role               = "roles/iam.serviceAccountUser"
  member             = var.os_login_member
}

output "public_ip" { value = google_compute_address.vpn.address }
output "name" { value = google_compute_instance.vpn.name }
# server-assigned: changes whenever the instance is replaced (provision.forget_replaced_hosts)
output "instance_id" { value = google_compute_instance.vpn.instance_id }
