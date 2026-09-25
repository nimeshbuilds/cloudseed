variable "project_id" { type = string }
variable "region" { type = string }
variable "prefix" { type = string }
variable "firewall_prefix" {
  description = "Prefix for firewall-rule names: the prefix itself, or a hashed short form when it is too long for GCP's 63-character limit."
  type        = string
}
variable "public_subnet_cidr" { type = string }
variable "private_subnet_cidr" { type = string }
variable "allowed_ssh_cidrs" { type = list(string) }

locals {
  bastion_tag = "${var.prefix}-bastion"
  private_tag = "${var.prefix}-private"
}

resource "google_compute_network" "this" {
  project                 = var.project_id
  name                    = "${var.prefix}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "public" {
  project                  = var.project_id
  name                     = "${var.prefix}-public"
  region                   = var.region
  network                  = google_compute_network.this.id
  ip_cidr_range            = var.public_subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "private" {
  project                  = var.project_id
  name                     = "${var.prefix}-private"
  region                   = var.region
  network                  = google_compute_network.this.id
  ip_cidr_range            = var.private_subnet_cidr
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ---- Egress for private workloads via Cloud NAT ----
resource "google_compute_router" "this" {
  project = var.project_id
  name    = "${var.prefix}-router"
  region  = var.region
  network = google_compute_network.this.id
}

resource "google_compute_router_nat" "this" {
  project                            = var.project_id
  name                               = "${var.prefix}-nat"
  region                             = var.region
  router                             = google_compute_router.this.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.private.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ---- Firewall ----
resource "google_compute_firewall" "allow_ssh_to_bastion" {
  project       = var.project_id
  name          = "${var.firewall_prefix}-allow-ssh-to-bastion"
  network       = google_compute_network.this.name
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = var.allowed_ssh_cidrs
  target_tags   = [local.bastion_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_ssh_from_bastion" {
  project     = var.project_id
  name        = "${var.firewall_prefix}-allow-ssh-from-bastion"
  network     = google_compute_network.this.name
  direction   = "INGRESS"
  priority    = 1000
  source_tags = [local.bastion_tag]
  target_tags = [local.private_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_private_internal" {
  project       = var.project_id
  name          = "${var.firewall_prefix}-allow-private-internal"
  network       = google_compute_network.this.name
  direction     = "INGRESS"
  priority      = 1100
  source_ranges = [var.private_subnet_cidr]
  target_tags   = [local.private_tag]

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }
}

# Explicit, logged deny so blocked attempts are visible.
resource "google_compute_firewall" "deny_all_ingress" {
  project       = var.project_id
  name          = "${var.firewall_prefix}-deny-all-ingress"
  network       = google_compute_network.this.name
  direction     = "INGRESS"
  priority      = 65000
  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

output "network_name" { value = google_compute_network.this.name }
output "network_self_link" { value = google_compute_network.this.self_link }
output "public_subnet_id" { value = google_compute_subnetwork.public.id }
output "private_subnet_id" { value = google_compute_subnetwork.private.id }
output "nat_name" { value = google_compute_router_nat.this.name }
output "bastion_tag" { value = local.bastion_tag }
output "private_tag" { value = local.private_tag }
