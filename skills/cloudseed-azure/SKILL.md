---
name: cloudseed-azure
description: Azure specifics for the cloudseed CLI - what `cloudseed setup azure` builds (VNet, NSGs, NAT gateway, bastion, Log Analytics, optional AKS / VPN / FIPS / Defender), its variables, outputs and gotchas (subscription ID, permissions, subscription-wide singletons). Use together with the cloudseed skill when the target cloud is Azure.
---

# cloudseed on Azure

`cloudseed setup azure --env <env> --subscription-id <id>` builds, in one location:

- **Resource group** `<name>-<env>-rg` holding everything.
- **VNet** (`network_cidr`) with `public` and `private` subnets (default outbound access disabled on both).
- **NSGs**: public subnet allows TCP/22 only from `allowed_ssh_cidrs` (priority 100) - with `enable_vpn` also UDP `vpn_port` (Tailscale: 41641) from the Internet to the VPN host only (AllowVPN, 110) - then denies all inbound; private subnet allows SSH from the public subnet (100), with `enable_vpn` everything from the VPN host (AllowFromVPN, 150; VPN clients are NATed behind it), traffic inside the private subnet (200), with AKS the pod CIDR of the overlay network (210) and TCP 80/443 from the bastion to the internal ingress (220), and AzureLoadBalancer health probes (300), then denies all inbound (4000). The deny rules are not logged (NSG / VNet flow logs are not managed).
- **NAT gateway** (Standard, static public IP) attached to the private subnet for egress.
- **Bastion VM**: Ubuntu 24.04 LTS (Ubuntu Pro FIPS 22.04 marketplace image when `fips_mode=true`; the terms are accepted for you), `Standard_B1s`, SSH key only, Trusted Launch (secure boot + vTPM), system-assigned managed identity, static Standard public IP. Login user = `admin_username` (default `azureuser`; names Azure reserves - admin, administrator, root, guest, test, user, ... - are refused at setup).
- **Logging baseline**: Log Analytics workspace (PerGB2018; `log_retention_days` 30-730 - Azure raises anything below 30 to 30) and the subscription Activity Log streamed into it. Optional Microsoft Defender for Cloud (`enable_defender=true`): Defender for Servers Plan 2 and Defender for Storage (`DefenderForStorageV2`); a sub-plan or extension an administrator changes later (agentless scanning, malware scanning, ...) is left alone.
- **Remote state** (when chosen): dedicated resource group + StorageV2 account (TLS 1.2, HTTPS only, no public blob access, blob versioning + soft delete) with a private `tfstate` container.
- **AKS** (optional, `enable_kubernetes=true`): private cluster (unless `kubernetes_public_endpoint=true`, whose authorized ranges are `allowed_ssh_cidrs` plus the NAT egress IP and the bastion; changing it later re-creates the cluster) in the private subnet; a private cluster also publishes its API server's private IP under a public DNS name (`<prefix>-<id>.hcp.<region>.azmk8s.io`), so kubectl works over the VPN or Tailscale and through the bastion tunnel while the API stays unreachable from the Internet (for an existing cluster, applying this is an in-place update); Azure CNI overlay, egress through the NAT gateway, workload identity + OIDC issuer, Azure Policy, control-plane logs (API server, audit-admin, controller manager, scheduler, autoscaler) in Log Analytics, autoscaling system pool (`fips_enabled` in FIPS mode). Changing the node size or FIPS mode rotates the system pool through a temporary pool `systemtmp`, which needs spare vCPU quota and subnet IPs. Managed identities for external-secrets and external-dns; Velero's storage account, container, identity and a custom role (its name ends with the first 8 characters of the subscription id, so same-named environments in two subscriptions of one tenant do not collide) are added by `cloudseed platform install velero`. After creation the pool is resized through the AKS API (`cloudseed node add|remove|scale`).
- **VPN host** (optional, `enable_vpn=true`): OpenVPN (default) or a Tailscale subnet router (`vpn_type=tailscale`, needs `TS_AUTHKEY`) in the public subnet (Ubuntu Pro FIPS image in FIPS mode).
- **FIPS 140** (optional, `fips_mode=true`, new environments only): Pro FIPS images for the bastion and VPN host, FIPS AKS node pool, RSA-4096 SSH keys (Azure refuses ECDSA; a key you bring must be RSA-3072 or larger); Tailscale, kubeadm and ed25519 keys are refused.
- Provider: azurerm `>= 4.65, < 5.0` (the remote-state storage root needs `>= 4.9`).

## Variables (`--var name=value`)

Complete list with defaults, generated from the Terraform: `cloudseed help variables azure`.

- Core: `network_cidr` (via `--cidr`; default: first free `10.N.0.0/16`), `subnet_newbits` (8), `admin_username` (`--admin-username`, azureuser), `bastion_vm_size` (Standard_B1s), `tags` (map, or `--tag K=V`).
- Baseline: `enable_activity_log` (true), `log_retention_days` (30), `enable_defender` (false).
- AKS: `enable_kubernetes` (false), `kubernetes_version` (null = current default), `kubernetes_node_size` (Standard_B2s), `kubernetes_node_count` (2; a count above `kubernetes_node_max` raises the max), `kubernetes_node_min` (1), `kubernetes_node_max` (4), `kubernetes_public_endpoint` (false).
- VPN: `enable_vpn` (false), `vpn_type` (openvpn | tailscale), `vpn_vm_size` (Standard_B1s), `vpn_port` (1194, OpenVPN UDP, 1-65535; Tailscale always uses 41641, which the `vpn_port` output reports).
- `fips_mode` (false).
- `platform_prereqs`: managed by `cloudseed platform install` - never set it by hand.
- Refused in `--var` (cloudseed sets them): `name` (`--name`), `environment` (`--env`), `location` (`--region`), `network_cidr` (`--cidr`), `allowed_ssh_cidrs` (`--allow-ip` / `update-ip`), `ssh_public_key` (`--ssh-public-key`), `tags` (`--tag`).

Shortcut flags: `--subscription-id` (a GUID; or `ARM_SUBSCRIPTION_ID` / `AZURE_SUBSCRIPTION_ID` / `az account show` - anything else is refused before Terraform runs; an `ARM_SUBSCRIPTION_ID` that is not a GUID is reported and setup never falls back to az's subscription instead: pass `--subscription-id`), `--admin-username`.

## Outputs

Complete list with descriptions: `cloudseed help outputs azure`.

- Core: `resource_group_name`, `location`, `vnet_id`, `public_subnet_id`, `private_subnet_id`, `nat_public_ip`, `bastion_public_ip`, `bastion_vm_id`, `bastion_instance_id` (the VM's unique vmId: it changes when the VM is re-created, and cloudseed then forgets the old SSH host key), `log_analytics_workspace_id`, `ssh_user`, `fips_mode`, `tenant_id`, `subscription_id` (both set with or without AKS).
- AKS: `kubernetes_cluster_name`, `kubernetes_endpoint`, `kubernetes_node_resource_group`, `kubernetes_external_secrets_client_id`, `kubernetes_external_dns_client_id`, `kubernetes_velero_client_id`, `kubernetes_velero_storage_account`, `kubernetes_velero_container`.
- VPN: `vpn_public_ip`, `vpn_instance_id`, `vpn_type`, `vpn_port`.

## Gotchas

- Permissions: the base environment needs Contributor; the Activity Log diagnostic setting is subscription-scoped (Contributor or `Microsoft.Insights/diagnosticSettings/write` at subscription scope, otherwise set `--var enable_activity_log=false`). AKS (`enable_kubernetes`) creates role assignments (Network Contributor, DNS Zone Contributor), which need Owner, Contributor + User Access Administrator, or Contributor + Role Based Access Control Administrator. Velero (`cloudseed platform install velero`) adds role assignments (its custom role, Storage Blob Data Contributor) and the custom role definition itself (`Microsoft.Authorization/roleDefinitions/write` at subscription scope), which only Owner or Contributor + User Access Administrator can create - Role Based Access Control Administrator cannot create role definitions. With Contributor alone they fail with 403 AuthorizationFailed.
- Subscription-wide singletons: Defender pricing and the Ubuntu Pro FIPS marketplace terms are settings of the whole subscription - enable Defender in one environment only. A destroy leaves both in place (it prints the `az` commands to turn them off). The Activity Log diagnostic setting counts against the limit of 5 per subscription.
- NSG flow logs are not created (they need Network Watcher wiring); mention this if the user asks for flow logs on Azure.
- `--tag` on Azure: names without `< > % & \ ? /` or control characters and at most 128 characters (every tag also lands on the storage accounts), values at most 256, and at most 43 names of your own (a resource holds 50 tags and cloudseed sets 7). With a private AKS cluster (`enable_kubernetes` without `kubernetes_public_endpoint`) at most 9: AKS copies the cluster's tags onto its private DNS zone, which holds 15, and cloudseed sets 6 on the cluster. Setup refuses anything else before Terraform runs.
- Credentials: `az login` (the Azure CLI must then be installed: Terraform reads that login through it; a login under `AZURE_CONFIG_DIR` is honoured) or the `ARM_CLIENT_ID`/`ARM_CLIENT_SECRET`/`ARM_TENANT_ID`/`ARM_SUBSCRIPTION_ID` env vars (service principal). A system-assigned managed identity needs only `ARM_USE_MSI=true`; OIDC needs `ARM_CLIENT_ID` plus `ARM_USE_OIDC=true` (an OIDC token alone does nothing). Never handle the values yourself.
- Tag names are case-insensitive: `--tag environment=x` sets `Environment` (and `--tag Environment=...` reaches every resource), a later run's spelling replaces a saved one, and two spellings in one run are refused.
- `--region` is checked against the Azure cloud `ARM_ENVIRONMENT` selects: `usgov*` / `usdod*` locations need `ARM_ENVIRONMENT=usgovernment`, `china*` need `ARM_ENVIRONMENT=china` (then also `az cloud set` and `az login`), and the default location follows it (`eastus`, `usgovvirginia` or `chinanorth3`). When `az` is logged in to that cloud its location list decides (an unknown location is refused, with a did-you-mean); otherwise an unknown location only gets a warning, so a location newer than cloudseed still works.
