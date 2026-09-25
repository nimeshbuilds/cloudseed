---
name: cloudseed-gcp
description: Google Cloud specifics for the cloudseed CLI - what `cloudseed setup gcp` builds (VPC, bastion, logging baseline, optional GKE / VPN / FIPS), its variables, outputs and gotchas (project ID, APIs, OS Login vs metadata keys, network tags, zones). Use together with the cloudseed skill when the target cloud is GCP.
---

# cloudseed on Google Cloud

`cloudseed setup gcp --env <env> --project-id <project>` builds, in one region/zone:

- **APIs** enabled: cloudresourcemanager, compute, iam, logging, monitoring, oslogin; with GKE also container, iamcredentials, secretmanager and dns (never disabled on destroy; `enable_apis=false` skips them).
- **Custom-mode VPC** with two subnets carved from `network_cidr`: `public` and `private` (Private Google Access on, VPC flow logs on both).
- **Cloud Router + Cloud NAT** for the private subnet only (error logging on).
- **Firewall**: SSH to bastion tag from `allowed_ssh_cidrs` (logged); SSH from bastion tag to private tag; internal traffic inside the private subnet; an explicit, logged deny-all ingress at priority 65000.
- **Bastion**: e2-micro Debian 12 (Ubuntu Pro FIPS 22.04 in FIPS mode), Shielded VM (secure boot, vTPM, integrity monitoring), static external IP, dedicated service account with only `logging.logWriter` + `monitoring.metricWriter`, project SSH keys blocked, in `zone` (default `<region>-a`; `<region>-b` in us-east1 and europe-west1, which have no `-a` zone; it must be inside the region). Login user = `ssh_username` (defaults to your local username) with metadata keys; with OS Login see Gotchas.
- **Logging baseline** (`enable_project_baseline`, one env per project): `_Default` log bucket retention set to `log_retention_days`; optional Data Access audit logs for all services (`enable_data_access_audit_logs`). Both are project-wide and kept on destroy (see Gotchas).
- **Remote state** (when chosen): GCS bucket, versioned, uniform bucket-level access, public access prevention enforced.
- **GKE** (optional, `enable_kubernetes=true`): private cluster in the private subnet (private nodes, private endpoint unless `kubernetes_public_endpoint=true`, control plane in `kubernetes_master_cidr`), VPC-native, Dataplane V2, Workload Identity, shielded COS nodes, autoscaling from max(`kubernetes_node_min`, `kubernetes_node_count`) - the count is the floor, 2 by default - up to max(`kubernetes_node_max`, `kubernetes_node_count`), control-plane logs (API server, scheduler, controller manager). Secrets are encrypted at rest with Google-managed keys (no application-layer KMS key). Workload Identity service accounts for external-secrets, external-dns and (via `cloudseed platform install velero`) velero, plus the Velero GCS bucket. kubectl needs `gke-gcloud-auth-plugin` (`gcloud components install gke-gcloud-auth-plugin`); after creation the node pool is resized through the GKE API (`cloudseed node add|remove|scale`).
- **VPN host** (optional, `enable_vpn=true`): OpenVPN (default) or a Tailscale subnet router (`vpn_type=tailscale`, needs `TS_AUTHKEY`) in the public subnet; project SSH keys blocked.
- **FIPS 140** (optional, `fips_mode=true`, new environments only): bastion and VPN host on the Ubuntu Pro FIPS 22.04 image (metered, no token needed), GKE on Container-Optimized OS, RSA-4096 SSH keys; Tailscale, kubeadm and ed25519 keys are refused.

## Variables (`--var name=value`)

Complete list with defaults, generated from the Terraform: `cloudseed help variables gcp`.

- Core: `network_cidr` (via `--cidr`; default: first free `10.N.0.0/16`), `subnet_newbits` (4), `zone` (`--zone`, default `<region>-a`, or `<region>-b` in us-east1 / europe-west1; must be inside the region), `ssh_username` (`--ssh-username`), `enable_os_login` (false), `os_login_member` (set by cloudseed from your gcloud account; refused in `--var`), `labels` (use `--tag K=V`; refused in `--var`).
- Bastion: `bastion_machine_type` (e2-micro), `bastion_image` (debian-cloud/debian-12), `bastion_disk_size` (10).
- Baseline: `enable_apis` (true), `enable_project_baseline` (true; set false for a second environment in the same project), `enable_data_access_audit_logs` (false), `log_retention_days` (90, 1-3650).
- GKE: `enable_kubernetes` (false), `kubernetes_version` (null = channel default), `kubernetes_node_size` (e2-standard-2), `kubernetes_node_count` (2, at least 1; also the autoscaler's floor), `kubernetes_node_min` (1; the effective minimum is never below `kubernetes_node_count`), `kubernetes_node_max` (4), `kubernetes_public_endpoint` (false), `kubernetes_master_cidr` (172.16.0.0/28).
- VPN: `enable_vpn` (false), `vpn_type` (openvpn | tailscale, any case), `vpn_machine_type` (e2-micro), `vpn_port` (1194, OpenVPN UDP, 1-65535; Tailscale always uses 41641).
- `fips_mode` (false).
- `platform_prereqs`: managed by `cloudseed platform install` - never set it by hand.

## Outputs

Complete list with descriptions: `cloudseed help outputs gcp`.

- Core: `project_id`, `region`, `network_name`, `network_self_link`, `public_subnet_id`, `private_subnet_id`, `nat_name`, `bastion_public_ip`, `bastion_name`, `bastion_instance_id`, `bastion_service_account`, `workload_network_tag` (put this tag on private VMs so the bastion can SSH to them), `ssh_user`, `fips_mode`.
- GKE: `kubernetes_cluster_name`, `kubernetes_endpoint`, `kubernetes_location`, `kubernetes_node_pool`, `kubernetes_master_version` (the running control-plane version at the last apply: `kubernetes_version` is only a minimum, the REGULAR channel upgrades past it; the bastion's kubectl follows it, so re-provision after an upgrade), `kubernetes_external_secrets_gsa`, `kubernetes_external_dns_gsa`, `kubernetes_velero_gsa`, `kubernetes_velero_bucket`.
- VPN: `vpn_public_ip`, `vpn_instance_id`, `vpn_type`, `vpn_port`.

## Gotchas

- The project must exist and billing must be enabled; cloudseed does not create projects or org policies.
- The Service Usage and Cloud Resource Manager APIs must already be enabled in the project that owns the credentials (the service account's project, or the gcloud quota project for ADC): cloudseed enables the other APIs through them.
- OS Login (`enable_os_login=true`) is automatic but needs the gcloud CLI logged in (`gcloud auth login`): setup registers the environment's key with that Google account, uses the account's POSIX username as the login user (not `ssh_username`) and grants it `roles/compute.osAdminLogin` on the bastion and VPN host plus `roles/iam.serviceAccountUser` on their service accounts. Users outside the project's organization also need `roles/compute.osLoginExternalUser` (granted at the organization).
- The OS Login key lives on the Google account, not in the project. cloudseed removes it again - after a full destroy, and after a setup that rotated the key or turned OS Login off - only when cloudseed added it (a key that was already registered, e.g. your own `--ssh-public-key`, is never removed) and no other environment logs in with it; when it cannot, it prints the command. Manual cleanup: `gcloud compute os-login ssh-keys list` and `gcloud compute os-login ssh-keys remove --key <fingerprint>`.
- A key registered with an expiry (outside cloudseed) that has expired or expires within the hour is registered again without one: cloudseed then owns it and removes it on destroy. A later expiry is only warned about (SSH stops working then).
- The `_Default` log retention and the Data Access audit config (allServices) are project-wide: let one environment per project manage them (`--var enable_project_baseline=false` for the others). A destroy keeps both, no longer managed: the retention stays at the value cloudseed set (Google never restores an earlier value; reset it with `gcloud logging buckets update _Default --location=global --retention-days=30 --project <project>`), and the allServices audit config stays on for the whole project. A setup or apply that would delete them (`enable_project_baseline=false`, `enable_data_access_audit_logs=false`) keeps them the same way: they are only dropped from the state, and the run prints how to change them by hand.
- Not every region has a `-a` zone: the default is `<region>-b` in us-east1 and europe-west1; pass `--zone` for another zone of the region.
- The default network is left in place (importing it is out of scope); recommend deleting it manually for a clean project.
- Labels on every resource: `project`, `environment`, `owner`, `managedby`, `cloudseedenv`, `cloudseedenvid` (reconcile reads them) plus `--tag K=V`.
- Credentials: `gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS`. Never handle key files yourself.
