# Private, VPC-native GKE cluster (Dataplane V2, Workload Identity, shielded nodes).
variable "project_id" { type = string }
variable "location" {
  description = "Zone or region of the control plane and node pool."
  type        = string
}
variable "node_locations" {
  type    = list(string)
  default = []
}
variable "region" {
  description = "Region for regional resources (the Velero GCS bucket): GCS rejects zones as bucket locations."
  type        = string
  validation {
    condition     = !can(regex("-[a-z]$", var.region))
    error_message = "region must be a region such as us-central1, not a zone."
  }
}
variable "prefix" { type = string }
variable "cluster_name" {
  description = "GKE cluster name (at most 40 characters); computed by the names module."
  type        = string
}
variable "node_pool_name" {
  description = "GKE node-pool name (at most 40 characters); computed by the names module."
  type        = string
}
variable "service_account_ids" {
  description = "Service-account IDs keyed gke_nodes/external_secrets/external_dns/velero; computed by the names module (valid and distinct)."
  type        = map(string)
}
variable "velero_bucket_name" {
  description = "Name of the Velero GCS bucket; computed by the names module."
  type        = string
}
variable "network_id" { type = string }
variable "subnetwork_id" { type = string }
variable "master_cidr" { type = string }
variable "authorized_cidrs" { type = list(string) }
variable "public_endpoint" { type = bool }
variable "kubernetes_version" { type = string }
variable "node_machine_type" { type = string }
variable "node_count" { type = number }
variable "node_min" { type = number }
variable "node_max" { type = number }
variable "private_network_tag" { type = string }
variable "labels" { type = map(string) }
variable "platform_prereqs" {
  description = "Cloud-side prerequisites for optional platform items (created on demand by `cs platform install`): velero."
  type        = list(string)
  default     = []
}

locals {
  name        = var.cluster_name
  want_velero = contains(var.platform_prereqs, "velero")
  # Workload Identity pool, taken from the cluster so every binding waits for it: the PROJECT.svc.id.goog pool only
  # exists once the first WI-enabled cluster does, and IAM rejects bindings to it before ("Identity Pool does not exist").
  workload_pool = google_container_cluster.this.workload_identity_config[0].workload_pool

  # The node pool's labels are Kubernetes node labels, not GCP labels: ASCII letters, digits, '_', '.' and '-',
  # starting and ending with a letter or digit (GCP labels may end in '-' and hold international letters). Labels that
  # are already valid stay exactly as they are; a key with nothing left is dropped, and when two GCP keys become the
  # same node-label key the first (in key order) wins. cloudseed/clouds/gcp.py _node_label mirrors this.
  node_labels_grouped = {
    for k, v in var.labels : trim(replace(k, "/[^a-z0-9_.-]+/", "-"), "-_.") => trim(replace(v, "/[^a-z0-9_.-]+/", "-"), "-_.")...
  }
  node_labels = { for k, vs in local.node_labels_grouped : k => vs[0] if k != "" }
}

resource "google_service_account" "nodes" {
  project      = var.project_id
  account_id   = var.service_account_ids["gke_nodes"]
  display_name = "${var.prefix} GKE nodes"
}

resource "google_project_iam_member" "nodes" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/artifactregistry.reader",
    "roles/stackdriver.resourceMetadata.writer",
  ])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.nodes.email}"
}

resource "google_container_cluster" "this" {
  project        = var.project_id
  name           = local.name
  location       = var.location
  node_locations = length(var.node_locations) > 0 ? var.node_locations : null

  network    = var.network_id
  subnetwork = var.subnetwork_id

  min_master_version       = var.kubernetes_version
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = false
  networking_mode          = "VPC_NATIVE"
  datapath_provider        = "ADVANCED_DATAPATH"
  enable_shielded_nodes    = true

  ip_allocation_policy {} # GKE-managed secondary ranges for pods/services

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = !var.public_endpoint
    master_ipv4_cidr_block  = var.master_cidr
  }

  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = toset(var.authorized_cidrs)
      content {
        cidr_block   = cidr_blocks.value
        display_name = cidr_blocks.value
      }
    }
  }

  release_channel {
    channel = "REGULAR"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  logging_config {
    # control-plane logs (API server, scheduler, controller manager) as well as system and workload logs
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS", "APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
    managed_prometheus {
      enabled = true
    }
  }

  resource_labels = var.labels

  # The temporary default pool (removed right after creation) must not run as the Compute Engine default service
  # account: it is often disabled in hardened projects, and the caller may not be allowed to act as it.
  node_config {
    service_account = google_service_account.nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }

  lifecycle {
    # node_config only shapes the temporary pool; afterwards the API reports the real pool's settings here, and
    # clusters created before this block existed must not be replaced
    ignore_changes = [node_config]
  }
}

resource "google_container_node_pool" "default" {
  project        = var.project_id
  name           = var.node_pool_name
  location       = var.location
  node_locations = length(var.node_locations) > 0 ? var.node_locations : null
  cluster        = google_container_cluster.this.name

  initial_node_count = var.node_count

  # kubernetes_node_count (what `cs node add/remove` changes) is the pool's floor, so the requested size is kept by
  # the autoscaler instead of being ignored; max always stays >= min.
  autoscaling {
    min_node_count = max(var.node_min, var.node_count)
    max_node_count = max(var.node_max, var.node_count, var.node_min)
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type    = var.node_machine_type
    image_type      = "COS_CONTAINERD" # in every mode: COS's kernel crypto module is FIPS 140 validated (fips_mode)
    disk_type       = "pd-balanced"
    disk_size_gb    = 50
    service_account = google_service_account.nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    tags            = [var.private_network_tag]
    labels          = local.node_labels

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  lifecycle {
    ignore_changes = [initial_node_count]
  }
}

output "cluster_name" { value = google_container_cluster.this.name }
output "endpoint" { value = google_container_cluster.this.endpoint }
output "location" { value = google_container_cluster.this.location }
output "node_pool_name" { value = google_container_node_pool.default.name }
# the running control-plane version: min_master_version is only a floor, the release channel upgrades past it
output "master_version" { value = google_container_cluster.this.master_version }

# ---- Workload Identity for platform controllers (external-secrets reads Secret Manager) ----
resource "google_service_account" "external_secrets" {
  project      = var.project_id
  account_id   = var.service_account_ids["external_secrets"]
  display_name = "${var.prefix} external-secrets"
}

resource "google_project_iam_member" "external_secrets" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.external_secrets.email}"
}

resource "google_service_account_iam_member" "external_secrets_wi" {
  service_account_id = google_service_account.external_secrets.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${local.workload_pool}[external-secrets/external-secrets]"
}

output "external_secrets_gsa" { value = google_service_account.external_secrets.email }
