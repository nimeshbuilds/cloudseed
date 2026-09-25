# Length-safe GCP resource names derived from "<name>-<env>" (pure functions: no provider, no resources).
#
# The CLI allows a 49-character prefix, but GCP limits are much tighter: service-account IDs 6-30 characters
# (unique per project), firewall names 63, GKE cluster and node-pool names 40, bucket names 63. Every name keeps
# its historical "<prefix>-<thing>" form whenever that form is valid (so existing environments are never renamed,
# which would replace the resources), and falls back to a truncated prefix plus a short hash of the full prefix
# when it is not. Nothing is ever silently truncated into a duplicate or into a trailing hyphen.

variable "prefix" { type = string }
variable "project_id" { type = string }

locals {
  hash = substr(sha1(var.prefix), 0, 4)

  # ---- service accounts: ^[a-z]([-a-z0-9]*[a-z0-9])?$, 6-30 characters, unique per project ----
  sa_suffix = {
    bastion          = "bastion"
    vpn              = "vpn"
    gke_nodes        = "gke-nodes"
    external_secrets = "external-secrets"
    external_dns     = "external-dns"
    velero           = "velero"
  }
  # short suffixes for the hashed form, so the full suffix always fits and every ID stays distinct
  sa_short = {
    bastion          = "bastion"
    vpn              = "vpn"
    gke_nodes        = "nodes"
    external_secrets = "eso"
    external_dns     = "edns"
    velero           = "velero"
  }
  # the historical IDs: substr("<prefix>-<suffix>", 0, 30)
  sa_legacy = { for k, s in local.sa_suffix : k => substr("${var.prefix}-${s}", 0, 30) }
  # a historical ID is kept only when it is valid and no other service account of the stack truncates to it
  sa_legacy_ok = {
    for k, id in local.sa_legacy : k => (
      can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]$", id)) &&
      length([for other in values(local.sa_legacy) : other if other == id]) == 1
    )
  }
  sa_ids = {
    for k, id in local.sa_legacy : k => (
      local.sa_legacy_ok[k] ? id :
      "${replace(substr(var.prefix, 0, 30 - length(local.sa_short[k]) - 6), "/-+$/", "")}-${local.hash}-${local.sa_short[k]}"
    )
  }

  # ---- firewall rules: 63 characters; the longest suffix is "-allow-ssh-from-bastion" (23) ----
  firewall_prefix = length(var.prefix) <= 40 ? var.prefix : "${replace(substr(var.prefix, 0, 35), "/-+$/", "")}-${local.hash}"

  # ---- GKE: cluster and node-pool names are limited to 40 characters ----
  gke_cluster = length("${var.prefix}-gke") <= 40 ? "${var.prefix}-gke" : "${replace(substr(var.prefix, 0, 31), "/-+$/", "")}-${local.hash}-gke"
  gke_pool    = length("${local.gke_cluster}-default") <= 40 ? "${local.gke_cluster}-default" : "default"

  # ---- Velero bucket: 3-63 characters, globally unique (hence the project ID or a hash of it) ----
  # Cloud Storage also refuses names that start with "goog" or contain "google" (or a close misspelling such as
  # "g00gle"): such a prefix gets a neutral "cs-" stem (cloudseed/clouds/gcp.py google_like says so at setup).
  google_like_prefix  = startswith(lower(var.prefix), "goog") || can(regex("g[o0]{2,}g[l1]e", lower(var.prefix)))
  velero_bucket_plain = "${lower(local.gke_cluster)}-velero-${var.project_id}"
  velero_bucket = (
    length(local.velero_bucket_plain) <= 63 && can(regex("^[a-z0-9][-a-z0-9_]*[a-z0-9]$", local.velero_bucket_plain)) &&
    !startswith(local.velero_bucket_plain, "goog") && !can(regex("g[o0]{2,}g[l1]e", local.velero_bucket_plain))
    ? local.velero_bucket_plain
    : "${local.google_like_prefix ? "cs" : replace(substr(lower(var.prefix), 0, 30), "/-+$/", "")}-velero-${substr(sha1("${var.prefix}/${var.project_id}"), 0, 12)}"
  )
}

output "service_account_ids" {
  description = "account_id of every service account the stack can create (bastion, vpn, gke_nodes, external_secrets, external_dns, velero)."
  value       = local.sa_ids

  precondition {
    condition     = alltrue([for id in values(local.sa_ids) : can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]$", id))])
    error_message = "Every service-account ID must be 6-30 characters of lowercase letters, digits and hyphens."
  }
  precondition {
    condition     = length(distinct(values(local.sa_ids))) == length(local.sa_ids)
    error_message = "Two service accounts of this stack would share one ID."
  }
}

output "firewall_prefix" {
  description = "Prefix for firewall-rule names (at most 40 characters)."
  value       = local.firewall_prefix
}

output "gke_cluster_name" {
  description = "GKE cluster name (at most 40 characters)."
  value       = local.gke_cluster
}

output "gke_node_pool_name" {
  description = "GKE node-pool name (at most 40 characters)."
  value       = local.gke_pool
}

output "velero_bucket_name" {
  description = "Name of the Velero GCS bucket (at most 63 characters)."
  value       = local.velero_bucket

  precondition {
    condition = (
      length(local.velero_bucket) <= 63 && can(regex("^[a-z0-9][-a-z0-9_]*[a-z0-9]$", local.velero_bucket)) &&
      !startswith(local.velero_bucket, "goog") && !can(regex("g[o0]{2,}g[l1]e", local.velero_bucket))
    )
    error_message = "The Velero bucket name must be a valid Cloud Storage name (at most 63 characters, no \"goog\" prefix, no \"google\")."
  }
}
