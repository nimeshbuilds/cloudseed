# Plan-level checks of the GCP stack with mock providers (no credentials, no cloud calls).
# Run: CLOUDSEED_TF_TESTS=1 python3 -m unittest tests.test_fix_core.TerraformModuleTests
#  or: terraform -chdir=terraform/gcp init -backend=false && terraform -chdir=terraform/gcp test

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = { email = "sa@proj-123456.iam.gserviceaccount.com" }
  }
  mock_resource "google_compute_network" {
    defaults = { self_link = "https://www.googleapis.com/compute/v1/projects/proj-123456/global/networks/net" }
  }
  mock_resource "google_compute_subnetwork" {
    defaults = { id = "projects/proj-123456/regions/us-east1/subnetworks/snet" }
  }
}

variables {
  project_id        = "proj-123456"
  region            = "us-east1"
  zone              = "us-east1-b"
  name              = "cs"
  environment       = "t"
  allowed_ssh_cidrs = ["203.0.113.5/32"]
  ssh_public_key    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC test"
  ssh_username      = "tester"
}

run "defaults_plan" {
  command = plan
  assert {
    condition     = output.vpn_port == null && output.vpn_type == null && output.kubernetes_cluster_name == null
    error_message = "optional features stay off by default"
  }
}

# A brand-new environment with GKE, the VPN and the velero prerequisites plans in one go.
run "fresh_kubernetes_vpn_velero" {
  command = plan
  variables {
    enable_kubernetes = true
    enable_vpn        = true
    platform_prereqs  = ["velero"]
  }
  assert {
    condition     = output.kubernetes_location == "us-east1-b" && output.vpn_port == 1194
    error_message = "the zonal cluster runs in the chosen zone; OpenVPN listens on vpn_port"
  }
}

run "fips_plan" {
  command = plan
  variables {
    fips_mode         = true
    enable_vpn        = true
    enable_kubernetes = true
  }
  assert {
    condition     = output.fips_mode
    error_message = "fips_mode is reported"
  }
}

# FIPS mode boots the VPN host (like the bastion) from the Ubuntu Pro FIPS image: nothing to attach at provisioning.
run "vpn_fips_image" {
  command = plan
  module {
    source = "./modules/vpn"
  }
  variables {
    prefix          = "cs-t"
    firewall_prefix = "cs-t"
    account_id      = "cs-t-vpn"
    network_name    = "net"
    subnetwork_id   = "projects/proj-123456/regions/us-east1/subnetworks/snet"
    private_tag     = "cs-t-private"
    vpn_type        = "openvpn"
    vpn_port        = 1194
    machine_type    = "e2-micro"
    fips_mode       = true
    labels          = {}
  }
  assert {
    condition     = google_compute_instance.vpn.boot_disk[0].initialize_params[0].image == "ubuntu-os-pro-cloud/ubuntu-pro-fips-2204-lts"
    error_message = "the FIPS VPN host must boot the Ubuntu Pro FIPS image"
  }
  assert {
    condition     = google_compute_address.vpn.region == "us-east1"
    error_message = "the VPN address lives in var.region (not a region parsed out of the zone)"
  }
}

run "vpn_plain_image_without_fips" {
  command = plan
  module {
    source = "./modules/vpn"
  }
  variables {
    prefix          = "cs-t"
    firewall_prefix = "cs-t"
    account_id      = "cs-t-vpn"
    network_name    = "net"
    subnetwork_id   = "projects/proj-123456/regions/us-east1/subnetworks/snet"
    private_tag     = "cs-t-private"
    vpn_type        = "openvpn"
    vpn_port        = 1194
    machine_type    = "e2-micro"
    labels          = {}
  }
  assert {
    condition     = google_compute_instance.vpn.boot_disk[0].initialize_params[0].image == "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
    error_message = "without FIPS the VPN host boots plain Ubuntu 24.04"
  }
}

run "tailscale_reports_its_port" {
  command = plan
  variables {
    enable_vpn = true
    vpn_type   = "tailscale"
  }
  assert {
    condition     = output.vpn_port == 41641 && output.vpn_type == "tailscale"
    error_message = "a Tailscale VPN host listens on 41641 (what the firewall opens), not the OpenVPN port"
  }
}

run "zone_outside_the_region_is_refused" {
  command = plan
  variables {
    zone = "us-central1-a"
  }
  expect_failures = [var.zone]
}

run "a_region_is_not_a_zone" {
  command = plan
  variables {
    zone = "us-east1"
  }
  expect_failures = [var.zone]
}

# The longest name/env pair the CLI accepts still yields valid service-account, firewall, GKE and bucket names.
run "long_names" {
  command = plan
  variables {
    name              = "abcdefghijklmnopqrstuvwx"
    environment       = "production-europe-west-a"
    enable_kubernetes = true
    enable_vpn        = true
    platform_prereqs  = ["velero"]
  }
}

# ---- wave 3 ----

# OS Login covers the VPN host too: no metadata key, enable-oslogin=TRUE and the same IAM grants as the bastion
# (an org enforcing constraints/compute.requireOsLogin refuses an instance that sets it to FALSE).
run "vpn_uses_os_login_like_the_bastion" {
  command = plan
  module {
    source = "./modules/vpn"
  }
  variables {
    prefix          = "cs-t"
    firewall_prefix = "cs-t"
    account_id      = "cs-t-vpn"
    network_name    = "net"
    subnetwork_id   = "projects/proj-123456/regions/us-east1/subnetworks/snet"
    private_tag     = "cs-t-private"
    vpn_type        = "openvpn"
    vpn_port        = 1194
    machine_type    = "e2-micro"
    enable_os_login = true
    os_login_member = "user:dev@example.com"
    labels          = {}
  }
  assert {
    condition     = google_compute_instance.vpn.metadata["enable-oslogin"] == "TRUE" && !contains(keys(google_compute_instance.vpn.metadata), "ssh-keys")
    error_message = "with OS Login the VPN host takes no metadata key"
  }
  assert {
    condition     = length(google_compute_instance_iam_member.os_admin_login) == 1 && length(google_service_account_iam_member.os_login_act_as) == 1
    error_message = "the OS Login member gets OS Admin Login on the VPN host and actAs on its service account"
  }
}

run "vpn_metadata_key_without_os_login" {
  command = plan
  module {
    source = "./modules/vpn"
  }
  variables {
    prefix          = "cs-t"
    firewall_prefix = "cs-t"
    account_id      = "cs-t-vpn"
    network_name    = "net"
    subnetwork_id   = "projects/proj-123456/regions/us-east1/subnetworks/snet"
    private_tag     = "cs-t-private"
    vpn_type        = "openvpn"
    vpn_port        = 1194
    machine_type    = "e2-micro"
    labels          = {}
  }
  assert {
    condition     = google_compute_instance.vpn.metadata["enable-oslogin"] == "FALSE" && startswith(google_compute_instance.vpn.metadata["ssh-keys"], "tester:ssh-ed25519 ")
    error_message = "without OS Login the VPN host keeps its metadata key"
  }
  assert {
    condition     = length(google_compute_instance_iam_member.os_admin_login) == 0
    error_message = "no OS Login grant without OS Login"
  }
}

# A --tag Environment=... wins over the built-in label everywhere (resource labels override the provider's
# default_labels, so the bastion/VPN/GKE must carry the same value).
run "environment_tag_override_wins" {
  command = plan
  variables {
    labels = { environment = "production", project = "cs" }
  }
  assert {
    condition     = local.labels["environment"] == "production"
    error_message = "the user's environment label is not overridden by var.environment"
  }
}

run "environment_label_defaults_to_the_env" {
  command = plan
  assert {
    condition     = local.labels["environment"] == "t"
    error_message = "without a label override the environment label is var.environment"
  }
}

# The project-wide logging settings: managed by default, left alone with enable_project_baseline=false.
run "project_baseline_on" {
  command = plan
  module {
    source = "./modules/security-baseline"
  }
  variables {
    enable_data_access_audit_logs = true
    log_retention_days            = 90
  }
  assert {
    condition     = length(google_logging_project_bucket_config.default) == 1 && length(google_project_iam_audit_config.all) == 1
    error_message = "the first environment of a project manages its logging settings"
  }
}

run "project_baseline_off" {
  command = plan
  module {
    source = "./modules/security-baseline"
  }
  variables {
    enable_project_baseline       = false
    enable_data_access_audit_logs = true
    log_retention_days            = 90
  }
  assert {
    condition     = length(google_logging_project_bucket_config.default) == 0 && length(google_project_iam_audit_config.all) == 0
    error_message = "enable_project_baseline=false leaves the project's logging settings alone"
  }
}

run "project_baseline_toggle_reaches_the_module" {
  command = plan
  variables {
    enable_project_baseline       = false
    enable_data_access_audit_logs = true
  }
}

# Values GCP would only refuse at apply time are refused by the plan.
run "log_retention_out_of_range" {
  command = plan
  variables {
    log_retention_days = 0
  }
  expect_failures = [var.log_retention_days]
}

run "log_retention_too_long" {
  command = plan
  variables {
    log_retention_days = 5000
  }
  expect_failures = [var.log_retention_days]
}

run "bastion_disk_below_the_image" {
  command = plan
  variables {
    bastion_disk_size = 5
  }
  expect_failures = [var.bastion_disk_size]
}

run "vpn_port_out_of_range" {
  command = plan
  variables {
    enable_vpn = true
    vpn_port   = 70000
  }
  expect_failures = [var.vpn_port]
}

run "vpn_port_zero" {
  command = plan
  variables {
    enable_vpn = true
    vpn_port   = 0
  }
  expect_failures = [var.vpn_port]
}

# A node pool needs at least one node; without a cluster the (unused) value never blocks a plan or a destroy.
run "empty_node_pool_is_refused" {
  command = plan
  variables {
    enable_kubernetes     = true
    kubernetes_node_count = 0
  }
  expect_failures = [var.kubernetes_node_count]
}

run "fractional_node_count_is_refused" {
  command = plan
  variables {
    enable_kubernetes     = true
    kubernetes_node_count = 1.5
  }
  expect_failures = [var.kubernetes_node_count]
}

run "unused_node_count_does_not_block" {
  command = plan
  variables {
    kubernetes_node_count = 0
  }
  assert {
    condition     = output.kubernetes_cluster_name == null
    error_message = "without a cluster the node count is not checked"
  }
}

run "empty_bastion_image" {
  command = plan
  variables {
    bastion_image = " "
  }
  expect_failures = [var.bastion_image]
}

run "upper_case_machine_types" {
  command = plan
  variables {
    bastion_machine_type = "E2-MICRO"
    vpn_machine_type     = "E2-MICRO"
    kubernetes_node_size = "E2-STANDARD-2"
  }
  expect_failures = [var.bastion_machine_type, var.vpn_machine_type, var.kubernetes_node_size]
}

run "custom_machine_types_are_accepted" {
  command = plan
  variables {
    bastion_machine_type = "e2-custom-2-4096"
    vpn_machine_type     = "n2-custom-4-8192-ext"
    kubernetes_node_size = "a2-highgpu-1g"
    enable_vpn           = true
    enable_kubernetes    = true
  }
}

# The instance ids change when a host is replaced (provision.forget_replaced_hosts drops its old SSH host key).
run "instance_ids" {
  command = apply
  variables {
    enable_vpn = true
  }
  assert {
    condition     = output.bastion_instance_id != null && output.vpn_instance_id != null
    error_message = "the bastion and the VPN host report their server-assigned instance ids"
  }
}

run "no_vpn_instance_id_without_a_vpn" {
  command = plan
  assert {
    condition     = output.vpn_instance_id == null
    error_message = "no VPN host, no instance id"
  }
}

# Cloud Storage refuses bucket names that start with "goog" or contain "google".
run "google_like_prefix_gets_a_neutral_velero_bucket" {
  command = plan
  module {
    source = "./modules/names"
  }
  variables {
    prefix = "google-lab-dev"
  }
  assert {
    condition     = startswith(output.velero_bucket_name, "cs-velero-") && !strcontains(output.velero_bucket_name, "google")
    error_message = "a google-like prefix never reaches the Velero bucket name"
  }
}

run "goog_prefix_gets_a_neutral_velero_bucket" {
  command = plan
  module {
    source = "./modules/names"
  }
  variables {
    prefix = "goog-dev"
  }
  assert {
    condition     = !startswith(output.velero_bucket_name, "goog")
    error_message = "a goog prefix never starts the Velero bucket name"
  }
}

run "ordinary_prefix_keeps_its_velero_bucket" {
  command = plan
  module {
    source = "./modules/names"
  }
  variables {
    prefix = "cs-t"
  }
  assert {
    condition     = output.velero_bucket_name == "cs-t-gke-velero-proj-123456"
    error_message = "names that were valid are unchanged"
  }
}

# GKE node labels are Kubernetes labels: ASCII, starting and ending with a letter or digit.
run "node_labels_are_kubernetes_safe" {
  command = plan
  module {
    source = "./modules/kubernetes"
  }
  variables {
    location            = "us-east1-b"
    prefix              = "lab-dv-"
    cluster_name        = "lab-dv--gke"
    node_pool_name      = "lab-dv--gke-default"
    service_account_ids = { gke_nodes = "lab-dv-gke-nodes", external_secrets = "lab-dv-eso", external_dns = "lab-dv-edns", velero = "lab-dv-velero" }
    velero_bucket_name  = "lab-dv-velero-proj-123456"
    network_id          = "https://www.googleapis.com/compute/v1/projects/proj-123456/global/networks/net"
    subnetwork_id       = "projects/proj-123456/regions/us-east1/subnetworks/snet"
    master_cidr         = "172.16.0.0/28"
    authorized_cidrs    = ["10.10.0.0/20"]
    public_endpoint     = false
    kubernetes_version  = null
    node_machine_type   = "e2-standard-2"
    node_count          = 2
    node_min            = 1
    node_max            = 4
    private_network_tag = "lab-dv-private"
    labels = {
      team         = "platform-eng-"
      "team-"      = "other"
      version      = "v1-2-"
      environment  = "dv-"
      "ключ"       = "значение"
      "donn-es"    = "données"
      managedby    = "cloudseed"
      cloudseedenv = "gcp-dv-"
      "_leading"   = "-x-"
      "t-1abc"     = "ok"
    }
  }
  assert {
    condition = google_container_node_pool.default.node_config[0].labels == tomap({
      team         = "platform-eng"
      version      = "v1-2"
      environment  = "dv"
      "donn-es"    = "donn-es"
      managedby    = "cloudseed"
      cloudseedenv = "gcp-dv"
      leading      = "x"
      "t-1abc"     = "ok"
    })
    error_message = "node labels are trimmed to the Kubernetes grammar; unrepresentable keys are dropped; the first key wins"
  }
  assert {
    condition     = google_container_cluster.this.resource_labels["team"] == "platform-eng-" && google_container_cluster.this.resource_labels["ключ"] == "значение"
    error_message = "the cluster's GCP resource labels keep the GCP form"
  }
}

run "production_topology" {
  command = plan
  module {
    source = "./modules/kubernetes"
  }
  variables {
    location            = "us-east1"
    node_locations      = ["us-east1-b", "us-east1-c", "us-east1-d"]
    prefix              = "lab-dv-"
    cluster_name        = "lab-dv--gke"
    node_pool_name      = "lab-dv--gke-default"
    service_account_ids = { gke_nodes = "lab-dv-gke-nodes", external_secrets = "lab-dv-eso", external_dns = "lab-dv-edns", velero = "lab-dv-velero" }
    velero_bucket_name  = "lab-dv-velero-proj-123456"
    network_id          = "https://www.googleapis.com/compute/v1/projects/proj-123456/global/networks/net"
    subnetwork_id       = "projects/proj-123456/regions/us-east1/subnetworks/snet"
    master_cidr         = "172.16.0.0/28"
    authorized_cidrs    = ["10.10.0.0/20"]
    public_endpoint     = false
    kubernetes_version  = null
    node_machine_type   = "e2-standard-2"
    node_count          = 2
    node_min            = 1
    node_max            = 4
    private_network_tag = "lab-dv-private"
    labels = {
      team         = "platform-eng-"
      "team-"      = "other"
      version      = "v1-2-"
      environment  = "dv-"
      "ключ"       = "значение"
      "donn-es"    = "données"
      managedby    = "cloudseed"
      cloudseedenv = "gcp-dv-"
      "_leading"   = "-x-"
      "t-1abc"     = "ok"
    }
  }
  assert {
    condition     = google_container_cluster.this.location == "us-east1" && toset(google_container_cluster.this.node_locations) == toset(["us-east1-b", "us-east1-c", "us-east1-d"]) && google_container_node_pool.default.location == "us-east1" && length(google_container_node_pool.default.node_locations) == 3
    error_message = "Regional GKE must place both the control plane and pool in the region with explicit node zones."
  }
}
run "regional_stack_location" {
  command = plan
  variables {
    enable_kubernetes         = true
    kubernetes_regional       = true
    kubernetes_node_locations = ["us-east1-b", "us-east1-c", "us-east1-d"]
  }
  assert {
    condition     = output.kubernetes_location == "us-east1"
    error_message = "The stack must pass its regional option into the real cluster."
  }
}
run "regional_missing_zones_rejected" {
  command = plan
  variables { kubernetes_regional = true }
  expect_failures = [var.kubernetes_node_locations]
}
run "regional_foreign_zone_rejected" {
  command = plan
  variables { kubernetes_node_locations = ["us-central1-a"] }
  expect_failures = [var.kubernetes_node_locations]
}
