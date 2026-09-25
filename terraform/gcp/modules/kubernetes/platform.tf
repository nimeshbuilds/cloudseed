# Cloud-side prerequisites for platform items installed by `cs platform install` (Workload Identity + storage).

# ---- external-dns: Cloud DNS records in this project ----
resource "google_service_account" "external_dns" {
  project      = var.project_id
  account_id   = var.service_account_ids["external_dns"]
  display_name = "${var.prefix} external-dns"
}

resource "google_project_iam_member" "external_dns" {
  project = var.project_id
  role    = "roles/dns.admin"
  member  = "serviceAccount:${google_service_account.external_dns.email}"
}

resource "google_service_account_iam_member" "external_dns_wi" {
  service_account_id = google_service_account.external_dns.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${local.workload_pool}[external-dns/external-dns]"
}

# ---- velero: GCS bucket, identity scoped to that bucket (file-system backups: no disk-snapshot permissions) ----
resource "google_storage_bucket" "velero" {
  count                       = local.want_velero ? 1 : 0
  project                     = var.project_id
  name                        = var.velero_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  labels                      = var.labels

  versioning { enabled = true }

  # keep overwritten/deleted backup objects for 30 days, not forever
  lifecycle_rule {
    condition {
      days_since_noncurrent_time = 30
      with_state                 = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_service_account" "velero" {
  count        = local.want_velero ? 1 : 0
  project      = var.project_id
  account_id   = var.service_account_ids["velero"]
  display_name = "${var.prefix} velero"
}

# Object access only on the Velero bucket (never project-wide: the project also holds the Terraform state bucket).
# Velero runs with snapshotsEnabled=false and file-system (kopia) backups, so it needs no compute permissions.
resource "google_storage_bucket_iam_member" "velero" {
  count  = local.want_velero ? 1 : 0
  bucket = google_storage_bucket.velero[0].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.velero[0].email}"
}

# The KSA velero/velero (the chart's server service account, named "velero" by the catalog) impersonates the GSA.
resource "google_service_account_iam_member" "velero_wi" {
  count              = local.want_velero ? 1 : 0
  service_account_id = google_service_account.velero[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${local.workload_pool}[velero/velero]"
}

# Under Workload Identity the GCP plugin signs download URLs (velero backup/restore describe --details, logs) with
# IAM signBlob on its own service account; grant that on the account itself, not project-wide (which would let it
# sign as any service account of the project).
resource "google_service_account_iam_member" "velero_sign" {
  count              = local.want_velero ? 1 : 0
  service_account_id = google_service_account.velero[0].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.velero[0].email}"
}

output "external_dns_gsa" { value = google_service_account.external_dns.email }
output "velero_gsa" { value = local.want_velero ? google_service_account.velero[0].email : null }
output "velero_bucket" { value = local.want_velero ? google_storage_bucket.velero[0].name : null }
