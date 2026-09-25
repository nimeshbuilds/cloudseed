---
title: "The cloudseed manual - every command, behaviour and limit on one page"
description: "The complete cloudseed reference on one page: what each target builds, the Kubernetes platform, resilience, FIPS, agents, MCP, the web console, undo, audit and known limits."
---

# The cloudseed manual

Everything cloudseed does, in one long page you can search with your browser: what each target builds, how the
commands behave, the security and credential model, and the known limits. The [guides](cli.md) walk through the same
features step by step, the [scenarios](../scenarios/index.md) are runnable walkthroughs, and the
[reference pages](../reference/index.md) (commands, variables, outputs, catalog, MCP tools) are generated from the code.

## Install and first run

Requires **Python 3.9+** (standard library only; the launchers check the version) and, for every target,
Terraform >= 1.10, which cloudseed can install for you.

```bash
git clone https://github.com/nimeshbuilds/cloudseed.git && cd cloudseed
./scripts/install.sh            # symlinks `cloudseed` (and the short alias `cs`) onto your PATH
cloudseed doctor                # shows what's installed / missing and how you're authenticated
cloudseed setup aws             # interactive: env name, region, state location, allowed IP, ...
```

`scripts/install.sh [DIR] [--alias NAME | --no-alias] [--force] [--uninstall]` links into `/usr/local/bin` when
writable, else `~/.local/bin`. An existing `cloudseed` or `cs` that is not this checkout's is never replaced: for
`cloudseed` the script stops and explains, an existing `cs` is left alone and the alias skipped (pick another name with
`--alias NAME`); `--force` moves the old file aside first. `make uninstall` (or `--uninstall`) removes the links again.

If Terraform is missing, `setup` asks how you'd like to get it (see *Dependencies*). Log in to the cloud
first (`aws configure`, `gcloud auth application-default login`, `az login`) or export the usual env vars.

Non-interactive example (CI, agents):

```bash
cloudseed setup gcp -y --env staging --project-id my-proj --region europe-west1 \
  --state remote --allow-ip 203.0.113.7 --var bastion_machine_type=e2-small --auto-approve
```

## What you get

| | AWS | GCP | Azure | VMware (local) |
|---|---|---|---|---|
| Network | VPC, 2+ AZs: public / private / isolated data subnets | custom VPC, public + private subnets, Private Google Access | VNet, public + private subnets, default outbound disabled; private NSG: SSH from the bastion subnet, the AKS pod CIDR, 80/443 from the bastion (AKS ingress), traffic from the VPN host (`enable_vpn`), AzureLoadBalancer probes, then deny-all | host-only private vmnet behind a NAT'd bastion |
| Egress | NAT gateway (single or per-AZ) | Cloud Router + Cloud NAT (private subnet only) | NAT gateway (private subnet) | bastion NATs the private network |
| Ingress | bastion SG: TCP/22 from your IP only; default SG stripped | firewall: SSH to bastion tag from your IP; logged deny-all | public NSG: SSH from your IP (+ the VPN port to the VPN host with `enable_vpn`), then deny-all inbound (not logged) | NAT network reachable from the host only; nftables on the bastion |
| Bastion | AL2023, IMDSv2, KMS-encrypted disk, EIP, SSM agent + role | e2-micro Shielded VM, dedicated least-privilege SA, static IP | Ubuntu 24.04 Trusted Launch, managed identity, static IP | Ubuntu/Debian cloud image, cloud-init, SSH key only |
| Workload access | `workload_security_group_id` (SSH only from bastion) | `workload_network_tag` | private NSG rule from bastion subnet | private IPs via bastion |
| Logging | VPC flow logs → KMS-encrypted CloudWatch | subnet flow logs, NAT logs, firewall logs, `_Default` retention | Activity Log → Log Analytics | auditd + sudo log on the bastion |
| Baseline | account-wide: CloudTrail (multi-region, validated, KMS), S3 public-access block, IAM password policy; per region: GuardDuty, Access Analyzer, EBS default encryption (aws/ebs key), optional Security Hub FSBP (with AWS Config recording) | required APIs, `_Default` log retention, optional Data Access audit logs | optional Defender for Servers/Storage | bastion: the same Ansible hardening; workload VMs: cloud-init with unattended security updates |
| Remote state | S3: versioned, SSE-KMS, TLS-only, native lockfile | GCS: versioned, uniform access, public-access prevention | Storage account: TLS1.2, HTTPS-only, versioning, soft delete | local state only |

Every resource is named `<name>-<env>-…` and tagged/labelled `Project=<name>`, `Environment=<env>`,
`ManagedBy=cloudseed`, `CloudseedEnv=<cloud>-<env>`, `CloudseedEnvId=<the environment's unique id>`, `Owner=<you>` plus
anything you add with `--tag` (reconcile uses these tags to tell this environment's resources from anyone else's). Tag
keys are case-insensitive (`--tag owner=alice` sets `Owner`), `--tag KEY=` removes a saved tag, and `ManagedBy`,
`CloudseedEnv` and `CloudseedEnvId` cannot be set. If you don't pick a name it defaults
to `cloudseed`; the network CIDR defaults to the first free `10.N.0.0/16` across all your environments so
they never overlap.

## Local VMs (VMware Fusion Pro / Workstation Pro)

`cloudseed setup vmware` builds the same environment shape on your own machine: a bastion VM (NAT + private
NIC, acting as gateway; cloud-init bootstrapped and Ansible-hardened like a cloud bastion) and optional private
workload VMs (cloud-init bootstrapped; they are not Ansible-hardened, but VMs created by this version turn on
unattended security updates themselves). Kubernetes nodes are hardened by the Kubernetes play and deliberately not
auto-updated. cloudseed detects Fusion Pro 13+ (macOS) or Workstation Pro 17+ (Linux; older releases are refused for
new environments). Windows detection is experimental; native environment changes are unsupported because locking
and a native Ansible control node are unavailable. Cloudseed detects the host architecture, downloads the matching official cloud image (Ubuntu 24.04/22.04, Debian 12 - Debian's `generic` image,
since the `genericcloud` kernel has no AHCI driver for the seed ISO; qcow2 converted with qemu-img), and drives
everything through **its own Terraform provider**
(`providers/vmdesktop`, Go; built once into `~/.cloudseed/providers`, which needs Go >= 1.25: `cloudseed doctor`
shows an older Go as too old and `cloudseed install go` upgrades it). Resources: `vmdesktop_network`,
`vmdesktop_vm`, data `vmdesktop_host`. The private network is VMware's built-in host-only vmnet, shared by every
environment without `--cidr`, so only one of those can have VMs at a time; a second one needs its own network
(`sudo vmrest`, `VMREST_USER`/`VMREST_PASSWORD` and `--cidr`, a private RFC 1918 range: a public one would hide the real
hosts of that range from your machine, and one containing 1.1.1.1 or 8.8.8.8 would also cut the VMs off from their
DNS). The VMs take fixed addresses below VMware's DHCP pool: bastion `.2`, workloads `.10+`, control planes `.20-.39`,
workers `.40-.99` (at most 60 on a /24; `.100-.127` are kept for MetalLB's LoadBalancer pool - an existing cluster with
more workers is warned, not refused). With Kubernetes on, setup refuses a network that overlaps the cluster's pod or
Service range (RKE2 `10.42.0.0/16` + `10.43.0.0/16`, kubeadm `10.244.0.0/16` + `10.96.0.0/16`) for a new environment or
when Kubernetes is turned on, and only warns for a cluster that already runs there. See `cloudseed help vmware`.

## Kubernetes platform (any cluster: EKS, GKE, AKS, RKE2, kubeadm)

- `cs env use <id>` picks the cluster you are working in (implicit when there is only one; asked otherwise); a name
  only one environment has works too (`cs env use prod` for `aws-prod`). `cs env show` and `cs env clear` take no id
  (`clear` accepts the current one's) - anything else exits 2.
- `cs node add|list|remove|scale`: scale managed pools in the cloud (EKS/GKE/AKS through the cloud API: `add` raises the
  pool and its autoscaler minimum, `remove` drains and deletes exactly that machine, `scale` sets size and limits); on
  VMware, Terraform creates the VM and Ansible joins it (a node whose fixed address would fall in MetalLB's
  LoadBalancer pool is refused).
- `cs platform install basek8s|scaling|data|ai|agentic|finops|devsecops|security|resilience|chaos|<item>`: a curated Helm/kustomize catalog (ArgoCD, metrics-server,
  kube-prometheus-stack, Loki 3 + Alloy log collection, OpenTelemetry operator, cert-manager with a cluster CA issuer, Gateway
  API + Envoy Gateway (private LB; MetalLB on local clusters), optional ingress-nginx and AWS LB controller, external-secrets,
  sealed-secrets, KEDA, VPA + Goldilocks, cluster-autoscaler/Karpenter, MinIO, CloudNativePG, Strimzi,
  Spark operator, Trino, StarRocks, Apache Polaris, Airflow, KubeRay, Kubeflow trainer/pipelines, KServe, JupyterHub, MLflow,
  vLLM stack, GPU operator, Ollama, kagent, kmcp, agentgateway, Qdrant, Langfuse, LiteLLM, Open WebUI) with values
  adapted to the target and distro, dependencies first, idempotent. Chart versions are pinned per cloudseed release;
  `--upgrade` re-applies installed items at the pinned version (and first refreshes the CRDs a chart keeps in `crds/`,
  which helm never upgrades). `--set key=value` is remembered per item and applied again by later installs and
  upgrades (`--set key-` forgets a key). `--set mode=ambient|sidecar` picks Istio's mode only when istio is part of the
  request (named, in a group, or a dependency such as kiali); otherwise `mode=...` is an ordinary chart value
  (`cs platform install minio --set mode=distributed`). kagent waits for `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`, the
  GitLab runner for `GITLAB_RUNNER_TOKEN` (`cs creds set NAME`); items published for amd64 only (harbor, litmus, gitlab,
  kubeflow-pipelines, vllm-stack) are skipped on all-arm64 clusters (Apple silicon VMware guests) unless `--force`;
  `install` exits 1 when nothing it was asked for can be installed. `uninstall` never removes shared dependencies,
  refuses items another installed item still needs (unless `--force`), forgets the item's remembered `--set` values
  (`cs undo` restores them) and keeps data: MinIO's volume and the Polaris database stay, and cloudnative-pg stays
  while Postgres clusters exist. A CRD chart whose CRDs still hold your objects is refused too; with `--force` those
  custom resources are saved first and `cs undo` creates them again after re-installing the chart.
- `cs kubectl|helm|k9s ...`: built-in tooling against the current cluster with a per-environment kubeconfig and an
  automatic SSH tunnel through the bastion for private cloud API endpoints. Missing tools are installed after asking
  (with `-y`: `cloudseed install <tool>` first); GKE also needs `gke-gcloud-auth-plugin`.

## Resilience, chaos, compliance, FIPS

- **Cloud prerequisites are part of the install.** Platform items that need cloud resources declare them, and
  `cs platform install <item>` applies them through the environment's own Terraform stack first (plan + approval as
  usual): Velero gets a versioned/encrypted/private bucket (S3, GCS, Azure Blob) and a least-privilege identity (IRSA,
  GKE Workload Identity, Azure workload identity + snapshot role); Karpenter gets its controller role, node role +
  instance profile + EKS access entry, SQS interruption queue, EventBridge rules and discovery tags; external-dns,
  external-secrets, the LB controller, the autoscaler and the EBS CSI driver get their identities with the cluster.
  `cluster-autoscaler` applies to every cloud: the EKS chart with IRSA, and GKE/AKS node pools are created with
  autoscaling (`kubernetes_node_min/max`; GKE never scales below `kubernetes_node_count`), so it shows as built in.
- **Disaster recovery** (`cs dr`, group `resilience`: Velero, kured, descheduler): `cs dr backup|restore|schedule` drive
  Velero with its CLI, fetched to match the server - only on your own run (a terminal, or `-y` with `--auto-approve` or
  `CLOUDSEED_AUTO_INSTALL=1`), never from an agent session; `cs dr status` and `cs dr backups` need no velero CLI.
  `cs dr describe|logs backup|restore <name> [--details]` show Velero's own view of one backup or restore with the
  environment's kubeconfig (without a velero CLI here, or with MinIO in the cluster, it runs in the velero pod).
  `cs dr test` is an automated drill - create a sample workload (with a volume
  holding a random file when a default StorageClass exists), back it up, delete it, restore it, verify every object and
  that the file came back (Completed PodVolumeBackups/Restores required), print PASS/FAIL with the measured restore time
  (exit 1 on FAIL); `--no-volume` skips the volume, `--volume` forces it (it then needs a default StorageClass or an
  unclassed PersistentVolume). `--keep` leaves the drill namespace and backup for inspection and prints the commands
  that remove them (`cs undo` does too); the kept backup has no drill TTL, so Velero keeps it for its default 30 days.
  Local clusters back up to MinIO, and their local-path StorageClass creates `local`
  volumes the Velero node agent can back up.
- **Chaos engineering** (`cs chaos`, group `chaos`: Chaos Mesh, LitmusChaos extra): `cs chaos run [basic|network|stress|full]`
  deploys a canary (or targets your Deployment with `--target ns/deploy`) and runs pod-kill, pod-failure, container-kill,
  network delay/loss/partition, DNS error, CPU/memory stress and time skew. Each experiment has a steady-state hypothesis
  (availability floor sampled from a probe pod, recovery bound); a fault Chaos Mesh never injected is an ERROR, the run is
  PASS, FAIL or INCONCLUSIVE and exits 0 only on PASS; the verdict table and JSON/Markdown reports are saved.
- **Scans** (`cs scan`): `cis` (kube-bench with the right benchmark per distro; the "default namespace should not be
  used" checks - EKS 4.5.2, GKE 4.6.4, AKS 4.6.3 - are decided by cloudseed listing that namespace with the
  environment's credentials; on a VMware RKE2 cluster whose CIS profile is off, failures come with the next step:
  `--var kubernetes_cis_profile=true`, then `cs provision vmware --env NAME --host k8s`), `kube` (kubescape NSA/MITRE/CIS),
  `images` (trivy-operator or one-off trivy), `host` (OpenSCAP + SCAP Security Guide CIS profile on bastion/VPN/local
  nodes), `stig` (DISA STIG profiles on Ubuntu 24.04, Ubuntu 22.04 with Ubuntu Pro and RHEL 8/9 hosts - the AL2023 AWS
  bastion and the Debian 12 GCP bastion have no STIG content and report n/a; EKS Kubernetes STIG via kube-bench), `cloud`
  (prowler CIS for the account/project/subscription; in AWS FIPS mode only the environment's region, through FIPS
  endpoints - the report's summary names them), `fips` (end-to-end FIPS verification; crypto-restricted items are
  reported as not FIPS-validated, and AWS FIPS environments also get live checks of `AWS_USE_FIPS_ENDPOINT` on the AWS
  controllers, Velero's s3-fips endpoint, Karpenter EC2NodeClass AMIs and '-fips' Bottlerocket node images; N/A on
  non-FIPS environments), `all` (FIPS verification only on FIPS environments). `--host bastion,vpn,k8s` picks the hosts
  (comma-separated; an unknown value exits 2). Reports under `<workdir>/scans/`, raw tool output
  under `<workdir>/scans/raw/`; `cs scan` exits 1 when a verdict is FAIL or `scan all` could not run a scan.
- **Well-Architected assessment** (`cs scan architecture <cloud> --env NAME --profile production --max-age-days 30 --json`):
  evaluates saved configuration and local evidence, with provider pillar mappings, findings and remediation.
  `--profile lab` relaxes production availability expectations. No cloud queries, installations or infrastructure
  changes; reports go under `<workdir>/scans/`. PASS exits 0, FAIL 1, INCOMPLETE 3 for missing/stale/manual evidence,
  invalid arguments 2. This scoped assessment is not live verification or certification. It is explicit and excluded
  from `scan all`. See [Well-Architected assessments](well-architected.md) for the CLI, MCP, console and skill workflows.
- **FIPS 140 mode** (`--var fips_mode=true` at creation): FIPS endpoints for AWS APIs and the S3 backend, Bottlerocket
  FIPS AMIs on EKS, `fips_enabled` AKS node pools, COS on GKE, Ubuntu Pro FIPS images for the GCP/Azure bastion and VPN
  host, AL2023 `fips-mode-setup` on the AWS bastion, Ubuntu Pro `fips-updates` on the AWS VPN host and on VMware
  (`UBUNTU_PRO_TOKEN`), verified reboot, FIPS-only sshd/OpenVPN algorithms, RSA-4096 SSH keys (ed25519 is not
  FIPS-approved and EC2/Azure refuse ECDSA), RKE2 only, TLS 1.2+/FIPS ciphers on the shared Gateway. Catalog items come
  in four tiers: compatible (installed), tls-restricted (Envoy Gateway and ingress-nginx: installed with FIPS TLS
  suites, flagged by `cs scan fips`), crypto-restricted (cert-manager, sealed-secrets, velero, cloudnative-pg: their
  job is cryptography in a non-validated module - installed and flagged) and the rest (application stacks with their
  own crypto: refused unless `--force`). Setup refuses kubeadm, Tailscale and ed25519 keys in FIPS mode; a setup that
  applies stops without `UBUNTU_PRO_TOKEN` where it is needed (`--dry-run` / `--plan-only` only warn). See
  `cs help fips`.

## Optional services

- **Kubernetes on VMware** (`--var enable_kubernetes=true` with `setup vmware`): control-plane and worker VMs on the
  private network with **RKE2** (default) or **kubeadm**, installed by Ansible from your machine; kubeconfig merged
  into `~/.kube/config` with `cloudseed k8s kubeconfig vmware`, which also makes it the current kubectl context. By
  default the first control plane installs RKE2's stable channel and later nodes join at the cluster's version;
  `--var kubernetes_version=v1.36.4+rke2r1` pins the release every new RKE2 node installs (kubeadm: `1.35`, the minor a
  new cluster starts with), and never upgrades a node that is already installed. RKE2's CIS hardening profile is off
  unless `--var kubernetes_cis_profile=true` (it enforces the restricted Pod Security Standard outside the exempt
  namespaces: RKE2's system ones plus `cloudseed-scan`, `velero`, `local-path-storage`, `minio` and `chaos-mesh`).
  Under it `cs platform install` labels the namespaces of catalog items whose pods need more than restricted before
  installing them - privileged: velero, local-path-provisioner, metallb, kube-prometheus-stack, falco, neuvector,
  kured, chaos-mesh, istio ambient, kubescape-operator, trivy-operator; baseline: minio, loki, alloy and similar - and
  `cs platform info <item>` shows the level.
- **Managed Kubernetes** (`--var enable_kubernetes=true`): private EKS / GKE / AKS in the private subnets with
  secure defaults (private API endpoint, control-plane logging - EKS to CloudWatch, GKE API server/scheduler/controller
  manager, AKS to Log Analytics - workload identity, autoscaling node pool). Secrets: KMS envelope encryption on EKS;
  GKE and AKS rely on the platform's encryption at rest (Google-/Microsoft-managed keys, no customer KMS key). A public
  AKS API (`kubernetes_public_endpoint=true`) also admits the NAT egress IP and the bastion.
  `cloudseed k8s kubeconfig <cloud> --env <name>` adds the cluster to your kubeconfig and makes it the current
  context (`cs undo` takes it out again and switches back; `cs kubectl` / `cs helm` need no setup at all); sizes and
  versions are `--var`-configurable.
- **VPN** (`--var enable_vpn=true`, cloud targets): a hardened VPN host in the public subnet. **OpenVPN** (default) is
  fully self-contained: Ansible builds the PKI, `cloudseed vpn add-user <cloud> --env <name> <user>` issues a client
  certificate and downloads an `.ovpn`, `cloudseed vpn connect <cloud> --env <name>` runs the client (installed after
  asking). **Tailscale** joins the host to your tailnet as a subnet router (`TS_AUTHKEY` needed at provisioning);
  `add-user`, `users` and `revoke` are OpenVPN's - with Tailscale, devices are managed in the tailnet. OpenVPN
  certificates live 825 days: `vpn status` shows the server certificate's expiry and each local profile's, `vpn users`
  each client's; renew the server's with `cloudseed vpn provision <cloud> --env <name>` and a client's with
  `cloudseed vpn add-user <cloud> --env <name> <user>`. `connect` and `disconnect` need root (sudo): without a terminal
  to type the password into (a console job, a scheduler) they use the askpass helper `SUDO_ASKPASS` (or sudo.conf)
  names, else `sudo -n`, and otherwise stop with the command to run in a terminal. On vmware there is no VPN:
  `vpn status` says so (exit 0) without Terraform.
- **Provisioning** (automatic after `setup`): the repository is copied to the bastion (and VPN host) and Ansible
  runs there: sshd hardening, fail2ban, unattended security updates, sysctl, auditd, a default-deny nftables host
  firewall (the SSH sources are enforced by the cloud firewall, so `update-ip` alone restores access; it also lifts
  a fail2ban ban of the new address), tools.
  Nothing from `~/.cloudseed` (state, keys) ever leaves your machine, and the copy leaves out private keys,
  kubeconfigs and credential files a checkout may hold (a file whose content is a private key stops it).
  `--no-harden` / `--no-firewall` also remove what an earlier run installed (the PAM and umask edits stay; VPN hosts
  and local bastions keep the NAT they forward with). A failed run or SSH wait prints the whole re-run command with
  the same `--host` / `--no-harden` / `--no-firewall` / `--no-tools` flags. With EKS / GKE / AKS the bastion also gets
  kubectl of the cluster's minor version (sha256-verified); on AWS run `aws eks update-kubeconfig --name <cluster>
  --region <region>` there, then kubectl. In AWS FIPS mode its login shells export `AWS_USE_FIPS_ENDPOINT=true`.

## Commands

```
cloudseed setup <cloud> [--env dev] [--name X] [--region R] [--state remote|local] [--cidr C]
                        [--allow-ip IP ...] [--ssh-public-key F] [--tag k=v] [--var k=v] [--advanced]
                        [--plan-only | --preview] [--dry-run] [--auto-approve] [-y]
cloudseed plan|apply|status|output <cloud> --env <name>
cloudseed destroy <cloud> --env <name>            # everything (type the env id to confirm)
cloudseed destroy <cloud> --env <name> --select   # pick modules/resources from a numbered list
cloudseed destroy <cloud> --env <name> --target module.stack.module.bastion   # also what depends on it (named first)
cloudseed destroy ... --purge-state --purge       # also remove the remote state storage / the working directory
cloudseed update-ip <cloud> --env <name>          # your public IP changed? update the SSH rule (cloud targets)
cloudseed ssh <cloud> --env <name> [-- extra ssh args]
cloudseed provision <cloud> --env <name> [--host bastion|vpn|k8s]   # re-run the Ansible hardening
cloudseed k8s info|kubeconfig|tunnel|untunnel <cloud> --env <name>
cloudseed vpn status|add-user|users|revoke|connect|disconnect|provision <cloud> --env <name> [user]
cloudseed env [show | use <cloud>-<env> | clear]                    # the cluster node/platform/kubectl/dr/... act on
cloudseed node add|list|remove|scale  ·  cloudseed platform list|info|plan|install|uninstall|status|ui|template ...
cloudseed dr status|backup|restore|backups|schedule|test [name] [<cloud> --env N]   # Velero, bucket + identity created for you
cloudseed dr describe|logs backup|restore <name> [--details] [<cloud> --env N]      # Velero's view of one backup / restore
cloudseed chaos run|list|status|stop|report [<cloud> --env N]      # Chaos Mesh experiments with verdicts
cloudseed scan cis|kube|images|host|stig|cloud|fips|all|reports [<cloud> --env N]   # compliance + vulnerability scans
cloudseed scan architecture [<cloud> --env N] [--profile production|lab] [--max-age-days 30] [--json]
cloudseed undo [<cloud> --env <name> | --global | --id ID] [--drop] [--list]   # revert (or drop) the previous action
cloudseed creds list|set|unset|clear  ·  cloudseed enable|disable agentic|headliner|mcp|ui
cloudseed list | doctor [cloud] | explain [name] [--json] | help [command|topic]
```

`status`, `output`, `inventory`, `troubleshoot`, `plan`, `ssh`, `k8s` and `vpn` may leave out `<cloud>`: they then act on
the environment named by `--env`, else the current one (`cs env use`), else the only one. `--env` also takes an
environment id as `cloudseed list` shows it (`--env aws-prod`, or `cs status aws-prod`). `<cloud>` without `--env`
means the only environment of that cloud; with several, `status`, `output`, `inventory`, `troubleshoot`, `plan`, `ssh`,
`k8s`, `vpn`, `finops` and `scan` use the current one, a terminal asks, and a script gets `dev` when it exists -
never a guess: several without a `dev` (or a current one that is not `dev`, for a command that changes things) stop
with the list. For `setup`, `--env` defaults to `dev`.

`setup` is idempotent: re-run it to change anything (it shows a plan first). Any stack variable except those cloudseed
sets itself can be overridden with `--var name=value`, read by the variable's declared type (text stays text, so
`kubernetes_version=1.30` is not a number; numbers, `true`/`false` and JSON lists/maps are decoded; `--var name=null`
drops a saved override); the same flag answers setup questions (`--var guest_os=debian-12`). Setup
refuses `name`, `environment`, `region`/`location`, the network CIDR, `allowed_ssh_cidrs`, `ssh_public_key`,
`tags`/`labels`, `platform_prereqs` (and on vmware `base_disk`/`guest_os_id`) and names the flag to use instead
(`--name`, `--env`, `--region`, `--cidr`, `--allow-ip`, `--ssh-public-key`, `--tag`, `platform install`, `guest_os`).
`--allow-ip` takes IPv4 addresses/ranges only and refuses `0.0.0.0/0`, anything wider than a /8 and lists covering
more than two /8s (two /8s are fine, adjacent or not). A range is written as its network (`203.0.113.0/24`), a single
address as itself or `/32`: an address with host bits and a prefix (`203.0.113.7/24`) is refused.
`setup --name` on a deployed environment renames (and so replaces) most of its resources: it warns, asks at a terminal,
and refuses an unattended apply (`--plan-only` first, then `cloudseed apply`). A plan with no changes exits 0; exit 3
means a plan is waiting for approval (`--auto-approve`). `--plan-only` saves the configuration for a later `apply`;
`--preview` plans without keeping anything (an existing environment keeps its configuration, a new one is not
created). A re-run (or `apply`) that would delete account-, subscription- or project-wide settings (e.g.
`enable_account_baseline=false`) keeps them in place and only drops them from the state, as a destroy does; on vmware,
node VMs a lower `kubernetes_workers` / `kubernetes_control_planes` deletes are drained and taken out of the cluster
first.
`cloudseed help variables <cloud>` lists every variable with its default (generated from `terraform/<cloud>/variables.tf`),
`cloudseed help outputs <cloud>` every output, and `cloudseed help <cloud>` (`vmware-skill` for vmware) adds what the
target builds and its gotchas. A first `setup --plan-only` with remote state plans the state storage and the stack and
creates nothing.

Every environment has a working directory that cloudseed creates: `~/.cloudseed/envs/<cloud>-<env>/` by default, or a
path you pass with `setup --workdir PATH` (a new or empty directory). It holds the config, generated SSH key, rendered
Terraform roots, local state (always local for vmware, plus the VM files under `vms/`), and provisioning artifacts.
Set `CLOUDSEED_HOME` to move the default location.

## Dependencies: three ways, you choose

| Mode | How | When |
|---|---|---|
| **Install locally** | `cloudseed deps install terraform [aws gcloud az \| all]` (its `all` is terraform aws gcloud az; `cloudseed install all` is the larger set with kubectl, helm, the VMware tools, VPN clients and skills) — Homebrew when present; otherwise terraform, kubectl, helm, go, k9s and databricks from their official releases (SHA256-verified) into `~/.cloudseed/bin`, aws and gcloud from the vendors' installers over HTTPS, az and snow with pip in their own virtualenv (Python 3.10+) | default on a workstation |
| **Container** | `cloudseed --runtime container setup aws` (or `cloudseed deps runtime container`). Builds `cloudseed:local` from the `Dockerfile` with Terraform + AWS CLI + gcloud + az + kubectl + helm, using **Docker or Podman** (asked once). `CLOUDSEED_HOME` is mounted at the same path (recorded paths stay valid), plus `~/.aws`, `~/.config/gcloud`, `~/.azure` and the cloud env vars; tools the container installs live in `~/.cloudseed/container-linux-<arch>/`, apart from the host's. | nothing installed, or you want isolation |
| **Single binary** | `cloudseed deps bundle` → `dist/cloudseed-<os>-<arch>` with the CLI, all Terraform modules and a verified Terraform release embedded | ship to machines with nothing on them |

When something required is missing, `setup` asks which of the three you want. Cloud CLIs are mostly optional:
cloudseed authenticates through Terraform's providers (env vars, profiles, ADC). The exception is Azure's `az login`:
the azurerm provider reads it through the Azure CLI, so `az` must be installed unless you use `ARM_*` service
principal, OIDC or managed-identity variables. Cluster commands need the cloud CLI to fetch credentials (asked for
when missing).

## Agentic mode (optional)

cloudseed is fully deterministic by default. You can also let an agent drive it:

```bash
cloudseed enable agentic              # picks the agent (built-in by default), installs what it needs, turns it on
cloudseed use builtin                 # built-in agent: talks to the Claude API directly, no extra CLI needed
cloudseed use claude                  # or codex, gemini, grok (custom agents: ~/.cloudseed/agents.json)
cloudseed model                       # shows available models for the selected agent, * = selected
cloudseed model claude-sonnet-5       # pick one
cloudseed agentic "create a staging env on aws in us-west-2 with 3 AZs"
cs agentic "list my environments"     # cs = short alias installed by scripts/install.sh; `do` also works
cloudseed disable headliner           # turn off the research brief (on by default)
cloudseed disable agentic
```

- **Built-in agent** (`use builtin`, the default): runs an agent loop in the CLI itself with the official
  Anthropic SDK (installed on first use into `~/.cloudseed/venv-agent`, so the core CLI stays dependency-free).
  Needs `ANTHROPIC_API_KEY` or an `ant auth login` profile; without them it automatically routes through your
  logged-in Claude Code CLI when present (subscription logins only work there). Its only tool is "run a `cloudseed` command":
  no shell, no file access. It follows the policy every agent session shares (see *Human-only commands* below):
  `agentic`, `enable`, `disable` and the changing forms of `install`, `deps`, `skill`, `creds`, `use`, `model`, `ui`
  and `mcp` are refused, and so are `ssh`, `k9s` (they need your terminal) and `mcp serve`; their read-only forms work
  (`creds list`, `model`, `use list`, `install list`, `ui status|logs`, `mcp status|guide|tools|config|test|logs`,
  `deps status`, `skill list|show`). Commands that change things
  pause for your approval: any `--auto-approve`, `--purge*`, `provision`, scans (all but `architecture`, `fips` and `reports`), vpn
  add-user/provision/revoke/connect/disconnect, platform install/ui, chaos run/stop, dr backup/schedule/test, mutating
  kubectl/helm (including options that point them at another server, identity or local file), helm template/lint,
  reading cluster secrets (`kubectl get secret` / `--raw`, `helm get values|all|manifest|hooks`,
  `helm status -o json|yaml`), and databricks/snowflake commands other than status/test. `destroy`, `undo`, node
  add/remove/scale, platform uninstall, `dr restore` and `chaos run --target` first run unasked as a preview (without
  `--auto-approve` they stop at exit 3, nothing changed), so you approve once, with the plan on screen. Refused and
  unapproved calls are shown to you too. Without a terminal approvals are refused unless
  `CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE` is `1`, `true`, `yes` or `on`.
  Models: `claude-opus-5` (default), `claude-opus-5-5`, `claude-fable-5-1`, `claude-sonnet-5`; refusal fallbacks are
  enabled. It puts the core `cloudseed` skill plus the skills the task needs into its prompt, with an index of the
  others (read on demand with `cloudseed skill show <name>`).
- **Skills**: `skills/` holds `SKILL.md` files in the Agent Skills format used by Claude Code, Codex, Gemini CLI and
  others: `cloudseed` (the driver) plus `cloudseed-aws`, `-gcp`, `-azure`, `-vmware`, `-destroy`, `-platform` (env,
  nodes, catalog, DR, chaos, scans), `-finops`, `-managed` (Databricks/Snowflake) and `-architecture`
  (Well-Architected assessments and implementation questions)
  (`cloudseed skill list` shows them, `cloudseed skill show <name>` prints one).
  `cloudseed skill install [names] [--agent claude|codex|gemini|grok] [--project] [--dir PATH]` copies them (all
  bundled skills without names; short names such as `aws`, `vmware`, `destroy` or `platform` work too) where the agent
  looks; `enable agentic`/`use` do this automatically. Grok cannot load skills from a directory: cloudseed sends the
  core skill and the task's skills in each Grok prompt, and `skill install --agent grok` installs them for Claude
  Code. With `cloudseed install skills ...` the words right after
  `skills` name skills (`install skills vmware` is the vmware skill, not the VMware tools).
- **Headliner**: before a task is handed to the agent, the CLI does the research itself — environments,
  outputs, tool/credential status, a command cheat-sheet — and prepends a compact brief, so the agent
  spends few tokens exploring. `cloudseed disable headliner` sends the bare task instead.
- **Agents**: `cloudseed agents` shows what each agent is and whether it is installed and logged in, with the
  exact fix when not (`npm install -g ...`, `gemini` login, `GROK_API_KEY`, ...). Each agent keeps only its own
  API key in its environment; every other secret is stripped. `cloudseed install <agent>` installs one and selects it
  only when no agent is selected yet (`cloudseed use` switches). Custom agents (`~/.cloudseed/agents.json`): `{prompt}`
  and `{model}` are replaced anywhere inside a word; without a model a bare `{model}` and the option right before it
  are dropped, and a word containing `{model}` is dropped (the codex template passes `--skip-git-repo-check`).
- **Human-only commands**: in every agent session (`CLOUDSEED_AGENT` set: the built-in agent, Claude Code, Codex,
  Gemini, Grok) the CLI itself refuses what changes your machine or cloudseed's settings - `creds set|unset|clear`,
  `use <agent>` (`use list` works), `model <id>`/`--forget`, `enable`/`disable`, `ui` (all but status/logs),
  `mcp` (all but status/guide/tools/config/test/serve/logs), `install` (all but list/help), `skill install`,
  `deps install|image|bundle|runtime`, `agentic`/`do` - with exit code 2 and the command for you to run. Codex and
  Grok have a full shell, so for them it stays advisory (the skills tell them the same).
- **Models**: each agent has a known model list; `cloudseed model <id>` accepts any id (unknown ones are
  remembered as custom).

### Credentials never leave your machine

- The brief and the task are passed through a **redactor** (AWS keys, private keys, JWTs, API keys,
  `password=`-style pairs) before reaching any agent.
- `cloudseed agentic` (alias `do`) **strips credential env vars** from the agent process (`AWS_SECRET_ACCESS_KEY`,
  `ARM_CLIENT_SECRET`, anything matching `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*API_KEY*`, …, and every secret stored in
  the `cs creds` vault). Child `cloudseed` commands get them back from a per-session unix socket (in a private temporary
  directory, protected by a random nonce), so nothing is written to disk and an agent running `env` sees nothing; the
  session ends when the agent exits or is stopped (SIGTERM/SIGHUP).
- All `cloudseed` output inside an agent session is **redacted line by line**, including the output of `cs kubectl`,
  `cs helm`, `cs databricks` and `cs snowflake`. Those run without a terminal there, so k9s, `kubectl edit` and
  `kubectl exec/attach/run/debug -i/-t` are refused, and so are calls that never end on their own (`logs -f`,
  `get -w`, `port-forward`, `proxy`: use `--tail`/`--since` or `kubectl wait --timeout`), a browser sign-in such as
  `databricks auth login`, prompts and the interactive `snow sql` shell (exit 2): run them in your own terminal.
- Claude Code is launched with only `Bash(cloudseed …)` / `Bash(cs …)` pre-approved and cloudseed's secret files
  denied: the vault (`credentials.json`), `gcp-credentials.json`, `managed.json` and `managed/` (data-platform
  connections), `vmware.json` (the vmrest login), `helm/` (registry logins), `mcp/` (the MCP token and the
  client-config backups that carry it), the UI token (`ui/token`), the session sockets (`sessions/`), the undo journal
  (`undo.json`) and its backups (`undo/`), every environment's `ssh/`, `k8s/`, `vpn/` and `platform/` (custom working
  directories included), any `*.ovpn`, plus `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.ssh`, `~/.kube`,
  `~/.docker/config.json` and `*.tfstate`. Codex, Gemini and Grok have no such rules: they can read any file you can,
  and only the skills tell them not to. (Templates per agent live in `cloudseed/agents.py`; override in
  `~/.cloudseed/agents.json`.)
- The `cs creds` vault refuses names that change how programs start, which code they load, which files or servers
  they trust, or where they send requests (`PATH`, `HOME`, `LD_*`/`DYLD_*`, `PYTHON*`, `ANSIBLE_*`, `OPENSSL_*`,
  `NODE_*`, `GIT_*`, `*_CONFIG`, `*_BASE_URL`, `*_ENDPOINT*`, proxies, `TF_LOG*`, `CLOUDSEED_*`, ...): its values reach
  every cloudseed process, so those belong in your shell. For GCP store the key file's path
  (`GOOGLE_APPLICATION_CREDENTIALS=/path/key.json`), or paste the file's JSON at the hidden prompt of
  `cs creds set GOOGLE_CREDENTIALS`.
- The stacks themselves keep no secrets in state or outputs (the bastion uses your public key only).

## Layout

```
assets/                    logo, icon and social banner (SVG + PNG)
ansible/                   playbooks bastion.yml, vpn.yml, kubernetes.yml, scan.yml (+ bootstrap.sh);
                           roles: common, hardening, tools, fips, openscap, openvpn, tailscale, k8s_common, rke2, kubeadm
bin/cloudseed              launcher (also the PyInstaller entry point)
cloudseed/                 CLI package (stdlib only): cli, help, explain, clouds/{aws,gcp,azure,vmware}, tf, reconcile,
                           deps, container, provision, localvm, services, platform, managed, finops, dr, chaos, scan, architecture,
                           troubleshoot, audit, undo, creds, secrets, skills, agents, builtin_agent, headliner, mcp,
                           operations, health, blueprints, guardrails, lifecycle, recovery, acceptance, releases, credential_store,
                           webui + web/ (console assets), netutil, paths, ui
terraform/<cloud>/         stack module: main.tf + modules/{network,bastion,security-baseline,kubernetes,vpn}
                           (+ kms on aws, names on gcp); tests/ holds its mocked `terraform test` suite
terraform/vmware/          local stack: modules/{bastion,workloads,kubernetes} (vmdesktop provider)
terraform/<cloud>-bootstrap/  remote state storage (aws, gcp, azure)
providers/vmdesktop/       cloudseed's own Terraform provider for VMware Fusion / Workstation (Go)
templates/gitlab-ci/       CI pipeline template (cs platform template gitlab-ci)
skills/                    agent skills (SKILL.md)
scripts/                   install.sh, build-bundle.sh, container-entrypoint.sh, gen-docs.py (docs/reference/ pages),
                           build-brand-assets.py (SVG artwork and optional PNG exports), live-acceptance.py, release-manifest.py
Makefile                   install, uninstall, fmt, validate, tftest, provider, test, image, bundle, clean
Dockerfile                 all-in-one runtime image
docs/ + mkdocs.yml         documentation site (MkDocs Material, theme overrides in overrides/): getting started,
                           19 scenarios, guides, and reference pages generated from the CLI by scripts/gen-docs.py
tests/                     unit tests (make test); make validate runs terraform validate on every root, make tftest
                           every terraform/*/tests suite (no cloud access); tests/scenarios/ runs every scenario page
```

Roots are rendered as `main.tf.json` per environment, so the checked-in Terraform stays generic.

## Web console: `cs enable ui`

One command starts a local, branded console (`http://127.0.0.1:7434/`, loopback only, no CDN or telemetry, runs as a
launchd/systemd user service) and opens it (`cs enable ui --no-open` starts it without a browser). It is
token-protected: the token comes in the link and is kept only in that browser tab (no cookie); API calls send it in
the `X-CS-Token` header. The server checks Host and Origin and forbids framing (`frame-ancestors 'none'`). Everything the CLI does is a form or a button there:
an environment wizard built from each cloud's questions (plan, dry-run, apply), environment cards (status, outputs,
troubleshoot, update IP, re-provision, SSH command, destroy), the whole platform catalog with install/plan/uninstall per
group or per item plus UI exposure, kubectl/helm/nodes, DR drills and backups, chaos suites, every scan, a reports viewer,
agents (enable, pick agent and model, run tasks, install skills), the MCP server (deploy, connect clients, guide), a local
credentials vault (`cs creds` from the terminal) and the help pages. Each action runs the same `cloudseed ...` command,
streams its output live, and lands in the audit trail; destructive actions need an explicit tick. `cs ui` reopens it,
`cs ui token` prints the link, `cs disable ui` removes it.

**A "?" explains anything in place.** It sits beside what the console shows: each view's title, every cloud, field and
question of the wizard (the stack variable it sets), an environment's target, bastion and Kubernetes / VPN / FIPS
chips, every platform group and item, the resilience cards, reports, agents and MCP, credentials, and every action
card and dialog. Hovering or focusing it shows a one-line summary and the `cs explain ...` command; clicking it opens
the Explain panel (a side sheet, a bottom sheet on phones) with the page `cs explain` prints, laid out as headings,
bullets and copyable commands. A Page | Terminal switch shows the exact CLI text, related pages and "did you mean" are
links (Back returns), and the footer copies the CLI command or shows the page full width (Open in Help). The panel
reads `GET /api/explain?q=<query>` and `/api/explain/names` with the token like every API call: documentation only,
answered at once, no job and no audit entry. ⌘K (Ctrl+K) also lists an `Explain: <name>` entry for everything
explainable, below the actions, and the Help page has an "Explain anything" search (typing `explain X` there opens the
panel).

Keyboard: ⌘K / Ctrl+K searches, `?` explains the page you are on, `1`-`0` switch views, `` ` `` shows or hides
Activity, ⌘B / Ctrl+B collapses the sidebar, Esc closes the explanation, a dialog or the palette, and Alt+← goes back
in the explanation (the Help page lists them).

## Undo

`cs undo` reverts the previous action from the CLI, the agents, the MCP server (`cloudseed_undo`, environment actions
only) and the web console (↶ Undo): setup changes, IP updates, node changes and cloud prerequisites restore the previous
configuration and re-apply (config.json is rewritten only once that worked); the first setup is undone by destroying
the environment; a full destroy keeps the config and keys so undo re-creates it (new hosts); platform installs are
uninstalled (and vice versa); VPN users revoked; backups and schedules deleted; a restore, mutating kubectl or helm
uninstall is rolled back to the Velero backup taken just before (an undo point of the whole cluster holds objects only:
the velero and minio namespaces and pod volumes are left out); scans/reports removed; MCP/agent/UI/credential toggles
reversed.

- **Fifteen real undo points per environment**, and fifteen for global actions, at most five of one kind: a burst of one
  kind of change (ten kubectl edits) only pushes out older changes of that kind, never the environment's creation, its
  platform installs or backups. Reports, scans, drills, chaos runs and "info" entries (e.g. a kubectl/helm change
  without Velero, which only says how to revert by hand) are minor: they have five slots of their own and never push a
  real undo point out.
- **What a configuration undo keeps safe**: local cluster nodes its plan deletes are drained and taken out of the
  cluster first (like `cs node remove`); account/subscription-wide settings it would delete are only dropped from the
  state, as a destroy does; Velero's bucket is never removed by an undo (it holds the backups). Undoing a restore or a
  mutating kubectl call deletes the objects and namespaces the change created before the Velero backup is restored.
- **Scope**: `cs undo` takes the newest entry anywhere (also among changes recorded within the same second);
  `cs undo <cloud> --env <name>` that environment's; a cloud or
  `--env` alone only narrows the choice (it asks, or stops, when several environments match), never widens it.
  `cs undo --global` takes the newest global entry; `--id ID` (from `cs undo --list`) a specific one, refused while a
  newer entry of its scope is left; `--drop` discards an entry that can never succeed instead of undoing it.
- **Global entries** (settings, agents, MCP, UI, credentials) are undone by you only: `cs undo --global` or the web
  console. When `CLOUDSEED_AGENT` is set (the MCP server, the built-in agent, external agents) they are skipped and
  `--global` is refused.
- `cs creds unset|clear` keep a copy of the removed values in the (0600) journal until newer global changes push that
  entry out of the history; `--forget` keeps none.
- **Undoing a file change never loses later edits**: `k8s kubeconfig` only takes out the contexts it merged (contexts
  other tools added since stay, and the previous current context comes back), and a file you changed since (a
  generated template, an installed skill) is copied aside - next to it as `<file>.cloudseed-undo-<time>`, a folder
  under `~/.cloudseed/undo-kept/` - before it is replaced or deleted. Settings undos (`env use`, `use`, `model`,
  `deps runtime`) restore only the keys that command changed; scans and reports remove only their own files. Undoing
  a `destroy --purge` puts the environment back into its own working directory (a custom `--workdir` is registered
  again) and makes it the current environment again when it was; for one that was never deployed that brings back its
  configuration, keys and history (inventory and audit trail).
- **Never racing Velero**: the undo of a `dr restore --no-wait` (or of one interrupted while waiting) is refused while
  that restore still runs, and the undo of a `dr test --keep` (it deletes the drill namespace and backup) while the
  backup is still being written; the entry is kept for later. `cs undo --list` shows the times in UTC.

`cs undo --list` shows the history (`cs help undo` has the full table). When it is exhausted, destroy the environment
and start over.

## MCP server: talk to cloudseed from Claude, Codex, Cursor, ...

```bash
cloudseed setup mcp          # deploys the server, connects the MCP clients you pick, prints the guide (saved to ~/.cloudseed/mcp/CONNECT.md)
cs mcp status                # health, service, which clients are connected      cs mcp guide     the guide again
cs mcp connect codex cursor  # add clients later (all | claude-code claude-desktop codex cursor windsurf gemini vscode)
cs destroy mcp               # stop + remove the service, the token and every client entry
```

`setup mcp` turns cloudseed into a Model Context Protocol server exposing **every feature as a tool** (48 tools; `cs mcp tools`
lists them: list / doctor / status / output / inventory / env, setup / plan / apply / update-ip / provision / install,
k8s / node / platform / kubectl / helm, ssh / vpn / managed (Databricks, Snowflake), finops / troubleshoot / explain /
help / skill, dr / chaos / scan, undo / destroy), plus **resources**
(`cloudseed://environments`, `cloudseed://skills/<name>` - the operating manuals), the **resource template**
`cloudseed://explain/{query}` (how anything works, as JSON) and **prompts** (create-environment, review-environment,
troubleshoot, teardown).

- **Deployment**: a Streamable-HTTP server on `http://127.0.0.1:7433/mcp` (legacy SSE at `/sse`) run as a launchd
  (macOS) or systemd `--user` (Linux) service that starts at login, protected by a bearer token (`~/.cloudseed/mcp/token`,
  0600). One server is shared by all clients; `cs mcp start|stop|restart|logs|token --rotate` manage it
  (`token --rotate` needs this HTTP deployment; clients connected over HTTP get the new token automatically). A
  `CLOUDSEED_HOME` other than `~/.cloudseed` gets its own service (`io.cloudseed.mcp.<home id>` /
  `cloudseed-mcp-<home id>`). `--transport stdio` skips the service: each client launches `cloudseed mcp serve` itself
  (no port, no token). `--no-auth` (no token, only for a client that cannot send headers) and `--no-service` (a
  detached process instead of the login service) are kept by later `setup mcp` runs; `--auth` / `--service` bring the
  token and the login service back without a terminal too (a script, the web console), at a terminal a re-run offers
  them back, and `--rotate-token` requires a token again (always a new one). `cs mcp start|restart` refuse while MCP is
  disabled (`cs enable mcp`).
- **Clients**: the command writes the config for what it detects - Claude Code (`claude mcp add -s user`), Claude Desktop
  (`claude_desktop_config.json`, stdio), Codex (`~/.codex/config.toml`), Cursor (`~/.cursor/mcp.json`), Windsurf, Gemini
  CLI (`~/.gemini/settings.json`), VS Code (`User/mcp.json`); `cs mcp config` prints snippets for anything else.
  `cs mcp connect|disconnect` take client names or `all` (at a terminal, without names, they ask about each client).
  A connected client keeps its transport unless `--transport` says otherwise; a new one gets http when the server is
  deployed, else stdio.
  `cs mcp connect` on a home where MCP was never set up enables it (stdio); after `disable mcp` / `destroy mcp` it
  connects the client but only warns that MCP is off.
- **Explain**: `cloudseed_explain` answers how any feature, target, command, topic, platform group or item, or setup
  variable works: the page `cs explain` prints, or with `format=json` the same page as data (kind, title, summary,
  sections, commands, also, did_you_mean), answered in-process with no child command; nothing found sets `isError` with
  the did-you-mean. The same JSON is the resource `cloudseed://explain/{query}` (listed by `resources/templates/list`):
  `{query}` is what `cs explain` takes, URL-encoded or with `/` between words (`vpn`, `target%20vmware`, `group/security`,
  `variable/aws/single_nat_gateway`), and `cloudseed://explain` alone is the index. The server's instructions tell agents
  to look there before guessing.
- **Guide**: after deploying, cloudseed prints how to verify the connection in each client, what you can ask ("plan a dev
  environment on AWS in us-west-2 with a private EKS cluster and show me the monthly estimate before applying"), the
  safety model and how to turn it off.
- **Safety**: loopback only, Origin validated, token required (unless deployed with `--no-auth`); every call is
  checked against the tool's schema (types, enums, required and unknown arguments) before it runs; tool calls run
  cloudseed as a child under the credential session broker with redacted output. Anything that changes
  infrastructure, a host or a service is marked
  `destructiveHint` and refuses to run without `confirm=true`, so the agent has to ask you first: setup with apply,
  apply, destroy, update-ip, provision, node add/remove/scale, platform install/uninstall/ui, vpn
  add-user/revoke/provision, ssh commands, install, mutating kubectl/helm, databricks/snowflake commands other than
  status/test/list/get/describe, scans (every kind except `architecture`, `fips` and `reports`), dr backup/restore/schedule/test, chaos
  run/stop and undo (`--drop` included). Reading Kubernetes Secrets or helm release values
  (`helm get values|all|manifest|hooks`, `helm status -o json|yaml`) needs `confirm=true` too: they can print
  passwords. Global actions
  (MCP/UI/credential/agent settings) can only be undone by you (`cs undo --global` or the web console), never through
  `cloudseed_undo`. A background service sees credential *files* (`~/.aws`, gcloud ADC, `az login`) but not variables
  exported in a shell - connect such a client over stdio instead.
- **Long calls**: setup/apply/destroy can run for many minutes. Codex and Gemini CLI entries get a 1-hour tool timeout;
  start Claude Code with `MCP_TOOL_TIMEOUT=3600000` if long calls time out. Cancelling a call in the client interrupts
  the command (Terraform stops cleanly and releases its lock).

## Audit trail, inventory, troubleshooting

Every command writes to the environment's working directory, no matter what: `logs/audit.jsonl` (who ran what,
when, exit code, and from where: `via` is `cli`, `ui` for the web console, or the agent - `mcp`, `builtin`,
`claude`, ...), `logs/<timestamp>-<command>.log` (full redacted output including Terraform, Ansible and SSH),
and `inventory.json` (every managed resource with its identifiers, outputs, and a history of applies, destroys,
provisioning and VPN changes); commands without an environment go to `~/.cloudseed/logs/audit.jsonl`. An unexpected
error keeps its redacted traceback in the environment's log, or without one in `~/.cloudseed/logs/<ts>-<cmd>-crash.log`
(0600); `CLOUDSEED_DEBUG=1` also prints it. `cloudseed troubleshoot <cloud> --env <env>` reads them deterministically,
recognises known failure signatures in the log of the failed change (a failed setup/apply/destroy/install comes before
read-only runs that failed after it; an unreadable local state is reported too), checks reachability, allowed IPs,
credentials, tools, VMware host/provider state and disk space, and prints fixes. `cloudseed inventory` shows what
exists.

Commands that change an environment (setup, plan, apply, destroy, update-ip, provision, undo, node, platform
install/uninstall/ui, and the Chaos Mesh / Velero installs of chaos run and dr) hold a per-environment lock while they
run. A second run on the same environment (another terminal, the web console, an MCP client or an agent) stops at
once with `<cloud>-<env> is busy`, naming the command that holds it, instead of racing it on the configuration and the
Terraform state. Read-only commands never wait.

`destroy --purge` keeps the audit trail and the final inventory under `~/.cloudseed/logs/purged/<cloud>-<env>/`;
config.json and the SSH keys go to the undo journal (`~/.cloudseed/undo/`) so `cs undo` can re-create the environment,
and are deleted with that entry. The default working directory goes entirely; from a new / empty `--workdir` only
cloudseed's own files are removed, and the directory itself only when nothing else is left in it (files you added
since stay). Before an EKS or
GKE cluster is destroyed, cloudseed deletes what Kubernetes created in the cloud (Karpenter nodes,
Gateway/Ingress/LoadBalancer load balancers, volumes of Delete-policy claims), so the cluster must be reachable.

## Help and errors

- `cloudseed help` (or just `cloudseed`) gives the overview; `cloudseed help <command>` explains every flag with
  examples; topics: `quickstart security state deps agentic agents envs services vmware platform fips destroy
  troubleshooting examples`; `cloudseed help variables|outputs <cloud>` is generated from the Terraform code. Pages
  are laid out for your terminal width. `cloudseed explain <name>` explains how anything is implemented
  (`cs explain feature|target|topic|command|group|item <name>` when a word names several things;
  `cs explain variable <cloud> <name>`, or just `cs explain <cloud> <name>`, is one setup setting with its default).
- The same explain pages everywhere: `cs explain <name> --json` prints one as data (query, found, kind, name, title,
  summary, sections, text, commands, also, did_you_mean, cli, error; exit 1 when nothing matches, with the
  did-you-mean), the web console shows it in its Explain panel from every "?" button, and MCP clients get it from
  `cloudseed_explain` (`format=json`) or the resource `cloudseed://explain/{query}`. One lookup serves them all, so they
  never disagree.
- `-y` (or `CLOUDSEED_NONINTERACTIVE=1`) never prompts: every answer comes from flags, env vars or defaults.
- Every error shows what went wrong, the likely fix, and correct examples for the command you were using
  ("did you mean" for typos, the help page when a topic is typed as a command, e.g. `cs quickstart`, the exact flag
  to pass in `-y` mode, and a diagnosis for Terraform failures such as expired credentials, GuardDuty already enabled,
  state locks, or missing permissions), laid out for the terminal's width like the help pages.
- `cloudseed doctor <cloud>` also checks credentials live through the cloud CLI when it is installed, and exits 1 when
  that cloud is not ready (a required tool missing or too old, no or invalid credentials); `cloudseed doctor` alone
  always exits 0.

## Notes and known limits

- The AWS security baseline has two halves, each a singleton. The account-wide half (`enable_account_baseline`:
  multi-region CloudTrail, S3 account public-access block, IAM password policy) belongs to **one** environment per
  account; the regional half (`enable_regional_baseline`, which follows the account-wide answer unless set: EBS
  encryption by default - it protects its region, not the account -, GuardDuty, IAM Access Analyzer, Security Hub /
  AWS Config) to one environment per account **and region**. A second environment in the same region:
  `--var enable_account_baseline=false`; one alone in another region:
  `--var enable_account_baseline=false --var enable_regional_baseline=true`. An existing GuardDuty detector,
  Security Hub or account analyzer (AWS allows one per region) is never adopted: while it is only on by default in
  this environment, setup leaves it alone and saves `enable_guardduty=false` / `enable_access_analyzer=false` with the
  environment; one you set true explicitly stops setup before anything changes - pass `--var enable_guardduty=false` /
  `enable_security_hub=false` / `--var enable_access_analyzer=false`. Security Hub turns on AWS
  Config recording (billed per recorded item; `--var enable_aws_config=false` where Config already records, e.g.
  Control Tower). AWS China and the isolated (ISO) regions are not supported.
- "Already exists" errors: cloudseed adopts only resources whose tags say they are this environment's (asking first, or
  `CLOUDSEED_ADOPT=1`, when the owner cannot be read) and refuses the rest. An adopted resource then belongs to the
  environment: destroy deletes it. After an adoption the new plan needs your approval again, and it is refused (even
  with `--auto-approve`) when it would delete or replace anything the plan you approved did not (`cs explain reconcile`).
- Azure: Defender pricing and the Ubuntu Pro FIPS image terms are subscription-wide (enable Defender in one
  environment only; destroy leaves both in place), and a subscription allows only five Activity Log diagnostic settings.
  `--region` is checked against the cloud `ARM_ENVIRONMENT` selects: `usgov*`/`usdod*` locations need
  `ARM_ENVIRONMENT=usgovernment`, `china*` need `ARM_ENVIRONMENT=china`, and the default location follows it
  (`usgovvirginia` / `chinanorth3`); when `az` is logged in its location list decides, otherwise an unknown location
  only gets a warning. Tag names may not contain `< > % & \ ? /` or control characters (at most 128 characters; values
  at most 256), and at most 43 `--tag` names are your own (cloudseed sets 7).
- Azure NSG flow logs and GCP org policies are not managed yet; GCP's default network is left untouched.
- GCP's `_Default` log retention and Data Access audit config (allServices) are project-wide: let one environment per
  project manage them (`--var enable_project_baseline=false` for the others). A destroy keeps both: the retention stays
  at the value cloudseed set (Google never restores an earlier one) and the audit logs stay on.
- Destroying an environment also deletes its CloudTrail bucket (audit logs) — that's what "clean slate" means. A full AWS
  destroy deletes CloudTrail, GuardDuty, Access Analyzer, Security Hub and the Config recorder, but leaves the S3
  account public-access block, EBS encryption by default, the IAM password policy and the AWS Config service-linked
  role in place (no longer managed): they protect the whole account (EBS encryption its region).
- Terraform >= 1.10 is required (S3 native locking). Providers: aws ~> 6, google 6–7, azurerm >= 4.65 (< 5; the Azure
  state storage root needs >= 4.9).
- SSH host keys are kept **per environment** (`<workdir>/ssh/known_hosts`), never in `~/.ssh/known_hosts`:
  re-created hosts reuse the same addresses and would otherwise be refused. `destroy` forgets them.
- `--var` must name a variable of the target's stack; unknown ones are refused at setup time
  (`cloudseed help variables <cloud>`). VPN, remote state and `update-ip` do not apply to `vmware` (the host-only
  network is reachable from your machine directly).
- On RKE2, cloudseed disables the bundled ingress controller (nginx / Traefik): its copy of the Gateway API
  CRDs would crash-loop against the platform's Envoy Gateway. `cs platform install ingress-nginx` if you want it.
- Helm 4 is supported: cloudseed uses its own registry/Docker config (no credential helpers) and takes field
  ownership on server-side apply. The Gateway API CRDs are pinned to the experimental channel that Envoy
  Gateway ships (v1.6.1); cloudseed lifts upstream's safe-upgrade policy when moving a cluster to it.
