# cloudseed GCP stack: VPC + Cloud NAT + firewall + bastion + logging baseline.

locals {
  prefix = "${var.name}-${var.environment}"
  # var.labels already carries project/environment/managedby/cloudseedenv/owner (the provider's default_labels);
  # only add what is missing, so a --tag Environment=... wins here too (resource labels override default_labels).
  labels = merge({
    environment = var.environment
  }, var.labels)
  required_apis = concat(
    [
      "cloudresourcemanager.googleapis.com", # every google_project_iam_member / audit config goes through it
      "compute.googleapis.com",
      "iam.googleapis.com",
      "logging.googleapis.com",
      "monitoring.googleapis.com",
      "oslogin.googleapis.com",
    ],
    var.enable_kubernetes ? [
      "container.googleapis.com",
      "iamcredentials.googleapis.com", # Workload Identity token exchange
      "secretmanager.googleapis.com",  # external-secrets (identity created below)
      "dns.googleapis.com",            # external-dns (identity created below)
    ] : [],
  )
}

resource "google_project_service" "apis" {
  for_each = var.enable_apis ? toset(local.required_apis) : toset([])

  project                    = var.project_id
  service                    = each.value
  disable_on_destroy         = false
  disable_dependent_services = false
}

# Length-safe names (service-account IDs, firewall rules, GKE, buckets) for any <name>-<env> the CLI accepts.
module "names" {
  source = "./modules/names"

  prefix     = local.prefix
  project_id = var.project_id
}

module "network" {
  source = "./modules/network"

  project_id          = var.project_id
  region              = var.region
  prefix              = local.prefix
  firewall_prefix     = module.names.firewall_prefix
  public_subnet_cidr  = cidrsubnet(var.network_cidr, var.subnet_newbits, 0)
  private_subnet_cidr = cidrsubnet(var.network_cidr, var.subnet_newbits, 1)
  allowed_ssh_cidrs   = var.allowed_ssh_cidrs

  depends_on = [google_project_service.apis]
}

module "bastion" {
  source = "./modules/bastion"

  project_id      = var.project_id
  region          = var.region
  zone            = var.zone
  prefix          = local.prefix
  account_id      = module.names.service_account_ids["bastion"]
  subnetwork_id   = module.network.public_subnet_id
  machine_type    = var.bastion_machine_type
  image           = var.fips_mode && var.bastion_image == "debian-cloud/debian-12" ? "ubuntu-os-pro-cloud/ubuntu-pro-fips-2204-lts" : var.bastion_image
  disk_size       = var.bastion_disk_size
  ssh_public_key  = var.ssh_public_key
  ssh_username    = var.ssh_username
  enable_os_login = var.enable_os_login
  os_login_member = var.os_login_member
  labels          = local.labels

  depends_on = [google_project_service.apis]
}

module "security_baseline" {
  source = "./modules/security-baseline"

  project_id                    = var.project_id
  enable_project_baseline       = var.enable_project_baseline
  enable_data_access_audit_logs = var.enable_data_access_audit_logs
  log_retention_days            = var.log_retention_days

  depends_on = [google_project_service.apis]
}

module "kubernetes" {
  count  = var.enable_kubernetes ? 1 : 0
  source = "./modules/kubernetes"

  project_id          = var.project_id
  location            = var.zone
  region              = var.region
  prefix              = local.prefix
  cluster_name        = module.names.gke_cluster_name
  node_pool_name      = module.names.gke_node_pool_name
  service_account_ids = module.names.service_account_ids
  velero_bucket_name  = module.names.velero_bucket_name
  network_id          = module.network.network_self_link
  subnetwork_id       = module.network.private_subnet_id
  master_cidr         = var.kubernetes_master_cidr
  authorized_cidrs    = concat([cidrsubnet(var.network_cidr, var.subnet_newbits, 0)], var.kubernetes_public_endpoint ? var.allowed_ssh_cidrs : [])
  public_endpoint     = var.kubernetes_public_endpoint
  kubernetes_version  = var.kubernetes_version
  node_machine_type   = var.kubernetes_node_size
  node_count          = var.kubernetes_node_count
  node_min            = var.kubernetes_node_min
  node_max            = var.kubernetes_node_max
  private_network_tag = module.network.private_tag
  labels              = local.labels
  platform_prereqs    = var.platform_prereqs

  depends_on = [google_project_service.apis]
}

module "vpn" {
  count  = var.enable_vpn ? 1 : 0
  source = "./modules/vpn"

  project_id        = var.project_id
  region            = var.region
  zone              = var.zone
  prefix            = local.prefix
  firewall_prefix   = module.names.firewall_prefix
  account_id        = module.names.service_account_ids["vpn"]
  network_name      = module.network.network_name
  subnetwork_id     = module.network.public_subnet_id
  private_tag       = module.network.private_tag
  vpn_type          = var.vpn_type
  vpn_port          = var.vpn_port
  allowed_ssh_cidrs = var.allowed_ssh_cidrs
  machine_type      = var.vpn_machine_type
  fips_mode         = var.fips_mode
  ssh_public_key    = var.ssh_public_key
  ssh_username      = var.ssh_username
  enable_os_login   = var.enable_os_login
  os_login_member   = var.os_login_member
  labels            = local.labels

  depends_on = [google_project_service.apis]
}
