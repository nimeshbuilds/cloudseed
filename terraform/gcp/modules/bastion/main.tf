variable "project_id" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "prefix" { type = string }
variable "account_id" {
  description = "Service-account ID (6-30 characters, unique in the project); computed by the names module."
  type        = string
}
variable "subnetwork_id" { type = string }
variable "machine_type" { type = string }
variable "image" { type = string }
variable "disk_size" { type = number }
variable "ssh_public_key" { type = string }
variable "ssh_username" { type = string }
variable "enable_os_login" { type = bool }
variable "os_login_member" {
  description = "IAM member (user:... or serviceAccount:...) that logs in through OS Login; granted OS Admin Login on the bastion and actAs on its service account. Empty: no grant."
  type        = string
  default     = ""
}
variable "labels" { type = map(string) }

# Dedicated, least-privilege service account (logs + metrics only).
resource "google_service_account" "bastion" {
  project      = var.project_id
  account_id   = var.account_id
  display_name = "${var.prefix} bastion"
}

resource "google_project_iam_member" "bastion_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.bastion.email}"
}

resource "google_project_iam_member" "bastion_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.bastion.email}"
}

resource "google_compute_address" "bastion" {
  project = var.project_id
  name    = "${var.prefix}-bastion"
  region  = var.region
}

resource "google_compute_instance" "bastion" {
  project      = var.project_id
  name         = "${var.prefix}-bastion"
  zone         = var.zone
  machine_type = var.machine_type
  tags         = ["${var.prefix}-bastion"]
  labels       = merge(var.labels, { role = "bastion" })

  boot_disk {
    initialize_params {
      image = var.image
      size  = var.disk_size
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = var.subnetwork_id
    access_config {
      nat_ip = google_compute_address.bastion.address
    }
  }

  metadata = merge(
    {
      enable-oslogin         = var.enable_os_login ? "TRUE" : "FALSE"
      block-project-ssh-keys = "TRUE"
    },
    var.enable_os_login ? {} : { ssh-keys = "${var.ssh_username}:${var.ssh_public_key}" }
  )

  metadata_startup_script = <<-EOT
    #!/bin/bash
    set -euo pipefail
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart ssh || systemctl restart sshd
  EOT

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  service_account {
    email  = google_service_account.bastion.email
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
  deletion_protection       = false
}

# OS Login: the SSH key lives in the user's Google profile (cloudseed registers it with gcloud) and access is IAM.
# Provisioning needs sudo (OS Admin Login), and a VM with an attached service account also needs actAs on it.
locals {
  os_login_grant = var.enable_os_login && var.os_login_member != ""
}

resource "google_compute_instance_iam_member" "os_admin_login" {
  count         = local.os_login_grant ? 1 : 0
  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.bastion.name
  role          = "roles/compute.osAdminLogin"
  member        = var.os_login_member
}

resource "google_service_account_iam_member" "os_login_act_as" {
  count              = local.os_login_grant ? 1 : 0
  service_account_id = google_service_account.bastion.name
  role               = "roles/iam.serviceAccountUser"
  member             = var.os_login_member
}

output "public_ip" { value = google_compute_address.bastion.address }
output "name" { value = google_compute_instance.bastion.name }
# server-assigned: changes whenever the instance is replaced (provision.forget_replaced_hosts)
output "instance_id" { value = google_compute_instance.bastion.instance_id }
output "service_account_email" { value = google_service_account.bastion.email }
