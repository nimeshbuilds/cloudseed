# Project-wide logging settings. Both are settings of the whole project, not of this environment: one environment per
# project manages them (enable_project_baseline=false for the others), and a destroy leaves them in place
# (cloudseed/clouds/gcp.py keep_on_destroy).
variable "project_id" { type = string }
variable "enable_project_baseline" {
  description = "Manage the project's logging settings from this environment (false for a second environment in the same project)."
  type        = bool
  default     = true
}
variable "enable_data_access_audit_logs" { type = bool }
variable "log_retention_days" { type = number }

# Admin Activity logs are always on; this adds Data Access logs when requested. Authoritative for allServices: it
# replaces any allServices audit config the project already had.
resource "google_project_iam_audit_config" "all" {
  count = var.enable_project_baseline && var.enable_data_access_audit_logs ? 1 : 0

  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# The _Default bucket always exists: "creating" it re-configures it, and deleting it only drops it from the state.
resource "google_logging_project_bucket_config" "default" {
  count = var.enable_project_baseline ? 1 : 0

  project        = var.project_id
  location       = "global"
  bucket_id      = "_Default"
  retention_days = var.log_retention_days
}

# environments created before enable_project_baseline existed: the same bucket config, now instance [0]
moved {
  from = google_logging_project_bucket_config.default
  to   = google_logging_project_bucket_config.default[0]
}
