"""Comprehensive, discoverable help: `cloudseed help [command|topic]`."""

from __future__ import annotations

import re
import textwrap

from . import __version__, paths, ui

OVERVIEW = f"""\
cloudseed {__version__} - secure multi-cloud landing zones (AWS, GCP, Azure, local VMware) with Terraform.

USAGE
  cloudseed <command> [options]      deterministic commands (always available)
  cloudseed agentic "<task>"         agentic: let an agent drive cloudseed (after `enable agentic`)
  cloudseed help [command | topic]   this help, per-command pages, and topic guides
  cs ...                             `cs` is a short alias for `cloudseed` (installed by scripts/install.sh)

CORE COMMANDS
  setup <cloud>      create or update an environment: network, subnets, NAT, bastion, security baseline
  plan <cloud>       show what apply would change
  apply <cloud>      re-apply the saved configuration
  destroy <cloud>    tear down everything, or pick parts with --select / --target
  status <cloud>     configuration, resource count and outputs
  output <cloud>     stack outputs (bastion IP, subnet IDs, ...)
  ssh <cloud>        SSH into the bastion with the generated key
  update-ip <cloud>  your public IP changed: re-detect it and re-apply the firewall
  provision <cloud>  copy this repo to the bastion / VPN host and harden them with Ansible (auto after setup)
  k8s <cloud>        the environment's cluster (EKS / GKE / AKS, RKE2 / kubeadm on vmware): info, kubeconfig,
                     tunnel, untunnel
  vpn <cloud>        VPN host: status, add-user, users, revoke, connect, disconnect, provision
  env                show | use <cloud>-<env> | clear: the environment cluster commands act on (else: the only
                     cluster, or you are asked)
  node               add | list | remove | scale: grow or shrink the cluster - managed pools in the cloud (scale sets
                     the size and the autoscaler limits), VM + auto-join (RKE2 / kubeadm) on vmware
  platform           list | info | plan | install | uninstall | status | ui | template: the Helm/kustomize catalog in
                     groups (basek8s scaling data ai agentic finops devsecops security resilience chaos) or single items
  kubectl|helm|k9s   run the tool against the current cluster (per-env kubeconfig, bastion tunnel; a missing tool is
                     installed after asking)
  ops                health, network, deployment profiles/specs, policy/expiry, drift, upgrades, recovery and acceptance
                     cs ops list --json shows every shared CLI/MCP/UI operation and its parameters
  finops             estimate | cloud | k8s | report: cloudseed estimate, provider bill, OpenCost allocation
  dr                 status | backups | backup | restore | schedule | test | describe | logs: disaster recovery with
                     Velero (bucket + identity created for you); `test` is an automated drill
  chaos              run | list | status | stop | report: Chaos Mesh experiments with a PASS/FAIL report
  scan               cis | kube | images | host | stig | cloud | fips | architecture | all | reports:
                     security scans and local Well-Architected assessments with saved reports
  databricks         Databricks: connect (profile per environment), test, or pass any CLI command through
  snowflake          Snowflake: the same, with the Snowflake CLI
  explain [name]     how anything works: a feature, target, command, topic, platform item or setup variable
                     (files, resources, controls, state, commands; --json: the page as data)
  undo [<cloud>]     undo the previous action (setup changes, installs, node changes, backups …), fifteen deep per
                     environment (five of one kind); `undo --global` for settings, agents, MCP, UI and credentials
  troubleshoot       deterministic diagnosis of an environment: audit log, the failed change, inventory, reachability
  inventory <cloud>  what exists in the environment (from state) and its change history
  list               all environments
  doctor [cloud]     tools, versions, credentials

INSTALL
  install <what...>  terraform | aws | gcloud | az | kubectl | helm | k9s | all | cloud | vmware | skills [names] |
                     <agent> | image | bundle   (cloudseed install list shows everything)
  deps               status | install <tool...> | image | bundle | runtime <mode>: install single tools locally, run
                     in Docker/Podman, or build a single binary

AGENTIC AND INTEGRATIONS (optional)
  enable ui          the local web console: everything here as forms and buttons (cs ui opens it again)
  creds              list | set | unset | clear: the local credential vault (cloud keys, API keys, tokens) used by
                     every command and the UI
  enable | disable   agentic | headliner | mcp | ui
  setup mcp          deploy the local MCP server (every feature as a tool) and connect Claude Code, Claude Desktop,
                     Codex, Cursor, ...
  mcp <subcommand>   status, guide, connect, disconnect, tools, config, test, serve, start, stop, restart, logs,
                     token, uninstall
  agents             what each agent is, whether it is installed and logged in
  use <agent>        builtin (Claude API, default) | claude | codex | gemini | grok
  model [id]         show or pick the model for the selected agent
  agentic "<task>"   run a natural-language task through the agent (alias: do)
  skill              list | install | show: the bundled agent skills

TOPICS  (cloudseed help <topic>)
  quickstart · security · state · deps · agentic · agents · envs · services · vmware · platform · fips · destroy ·
  troubleshooting · examples · variables <cloud> · outputs <cloud> · aws · gcp · azure · vmware-skill (per-target
  reference: what is built, every variable and output)

Targets: aws | gcp | azure | vmware (local VMs on Fusion Pro / Workstation Pro).
Global flags (before the command): -y/--yes (never prompt), --runtime local|container, --engine docker|podman. Most
commands also accept them after it; for kubectl, helm, k9s, ssh, databricks, snowflake and agentic put them before
(what follows those commands is handed to the tool or the agent).
Environment variables: CLOUDSEED_HOME (where everything lives), CLOUDSEED_NONINTERACTIVE=1 (same as -y),
CLOUDSEED_DEBUG=1 (print the redacted traceback of an unexpected error; it is always kept in a crash log).
Env shorthand: status, output, inventory, troubleshoot, plan, ssh, k8s and vpn may leave out <cloud>: they act on the
environment named by --env, else the current one (cs env use), else the only one (e.g. cs status, cs ssh --env lab).
--env also takes an environment id as `cs list` shows it (--env aws-prod, or cs status aws-prod).
<cloud> without --env: the only environment of that cloud. With several: status, output, inventory, troubleshoot, plan,
ssh, k8s, vpn, finops and scan use the current one; otherwise a terminal asks, and a script gets dev when it exists.
Several without a dev (or a current one that is not dev, for a command that changes things) stop with the list.
Deterministic vs agentic: `cloudseed setup aws` runs exactly that; `cloudseed agentic "set up aws"` asks the agent to do it.
Home: {paths.HOME}   (override with CLOUDSEED_HOME)
"""

COMMANDS: dict[str, str] = {
    "setup": """\
cloudseed setup <aws|gcp|azure|vmware> [--env NAME] [options]
cloudseed setup mcp                     deploy the local MCP server for Claude / Codex / Cursor / ... (see: cloudseed help mcp)

Creates a new environment or updates an existing one. Interactive by default: it asks for the
environment name, infrastructure name, region, state location, allowed SSH source, and the
cloud-specific inputs, then plans and (after confirmation) applies. Re-running setup with new
answers/flags updates the environment in place.

WHAT IT BUILDS
  - network with public / private (and on AWS isolated data) subnets, NAT for private egress
  - hardened bastion in the public subnet, SSH on 22 only from --allow-ip (default: your public IP)
  - a workload security group / network tag that only accepts SSH from the bastion
  - flow logs and a cloud-specific security baseline (see `cloudseed help <cloud>` skills)
  - optional remote state storage (hardened bucket / storage account) created first

OPTIONS
  --env NAME              environment name (asked at a terminal; default: dev). Env id becomes <cloud>-<NAME>. The id
                          of an existing environment (--env aws-dev) is not taken as a new name: use its name (--env dev)
  --name NAME             infrastructure name: prefixes every resource and sets Project=<NAME> tag (default: cloudseed).
                          Changing it on a deployed environment replaces most resources: it warns, a terminal asks,
                          and an unattended apply is refused (--plan-only first, then cloudseed apply)
  --region R              region / location (defaults: us-east-1, us-central1, eastus or AWS_REGION etc.). AWS China
                          (cn-*) and the isolated (ISO) regions are refused. Azure: checked against the cloud
                          ARM_ENVIRONMENT selects - usgov*/usdod* locations need ARM_ENVIRONMENT=usgovernment, china*
                          need ARM_ENVIRONMENT=china, and the default follows it (usgovvirginia / chinanorth3); an
                          unknown location is refused when az is logged in (its list decides), otherwise only warned
                          about
  --state remote|local    where Terraform state lives (default: remote, created for you; vmware: always local)
  --workdir PATH          working directory for the environment: config, SSH key, rendered Terraform, local
                          state, provisioning artifacts and (vmware) the VM files. Created by cloudseed: a new
                          or empty directory. Default: ~/.cloudseed/envs/<cloud>-<env>
  --cidr CIDR             network range (default: first free 10.N.0.0/16 across all your envs)
  --allow-ip IP|CIDR      SSH source for the bastion; repeatable or comma-separated (default: detected public IP).
                          IPv4 only. A range is written as its network (203.0.113.0/24) or as one address (/32):
                          203.0.113.7/24 is refused. 0.0.0.0/0, a range wider than a /8, or a list covering more
                          than two /8s is refused (two /8s are fine, adjacent or not)
  --ssh-public-key FILE   use this key instead of generating one; add --ssh-private-key FILE (its private half) so
                          `cloudseed ssh` and provisioning can log in with it
  --tag K=V               extra tag/label on every resource (repeatable). Keys are case-insensitive (owner=alice sets
                          Owner); K= removes a saved tag. ManagedBy, CloudseedEnv and CloudseedEnvId are cloudseed's
                          own (they mark what this environment created) and cannot be set
  --var K=V               override a stack variable or answer a setup question (repeatable); K=null drops a saved
                          override. The value is read by the variable's declared type: text stays text
                          (kubernetes_version=1.30), numbers / true|false / JSON lists and maps are decoded.
                          Variables cloudseed sets itself (name, environment, region/location, the network CIDR,
                          allowed_ssh_cidrs, ssh_public_key, tags/labels, platform_prereqs; vmware: base_disk,
                          guest_os_id) are refused with the flag to use instead; an unknown name is refused with a
                          did-you-mean - see `help variables <cloud>`
  --advanced              also prompt for advanced options (AZ count, NAT mode, instance sizes, ...)
  --plan-only             stop after the plan (a first run with remote state plans the state storage and the stack
                          and creates nothing); the configuration is saved, so `cloudseed apply` applies it later
  --preview               plan without keeping anything: an existing environment keeps its previous configuration
                          and a new one is not created (what the MCP tool and the web console run to show a plan)
  --dry-run               render + terraform validate only; touches nothing in the cloud
  --auto-approve          apply without asking. Without it and without a terminal (or with -y) setup shows the plan
                          and exits 3, nothing applied; a plan with no changes exits 0
  -y, --yes               non-interactive: never prompt, use flags/env vars/defaults (CLOUDSEED_NONINTERACTIVE=1
                          does the same for every command)
  --no-provision          skip the automatic provisioning (repo sync + Ansible hardening) after apply
  --no-harden, --no-firewall, --no-tools
                          provision without the OS hardening role / the nftables host firewall / the tools role
                          (--no-harden / --no-firewall also remove what an earlier run installed; see help provision)
  --profile P             [aws] CLI profile (or AWS_PROFILE)
  --project-id ID         [gcp] project (or GOOGLE_PROJECT, GOOGLE_CLOUD_PROJECT, CLOUDSDK_CORE_PROJECT, GCLOUD_PROJECT)
  --zone Z                [gcp] zone of the bastion, VPN host and GKE cluster, inside --region (default <region>-a;
                          <region>-b in us-east1 and europe-west1, which have no -a zone)
  --ssh-username U        [gcp, vmware] login user on the VMs (default: your local username)
  --subscription-id ID    [azure] subscription GUID (or ARM_SUBSCRIPTION_ID, AZURE_SUBSCRIPTION_ID, az account show)
  --admin-username U      [azure] admin user on the bastion (default azureuser; Azure-reserved names such as admin,
                          administrator, root, guest or test are refused)

CHANGING AN ENVIRONMENT
  A re-run (or `cloudseed apply`) shows the plan before anything changes. Account-, subscription- or project-wide
  settings the plan would delete (AWS: the S3 account public-access block, EBS encryption by default, the password
  policy and the AWS Config service-linked role, e.g. when enable_account_baseline goes false; GCP: the _Default
  retention and the allServices audit config; Azure: Defender plans and the Ubuntu Pro FIPS image terms) are kept in
  place and only dropped from the state, as a destroy does. On vmware, node VMs
  that a lower kubernetes_workers / kubernetes_control_planes deletes are drained and taken out of the cluster first,
  as `cs node remove` does. A GuardDuty detector or account Access Analyzer that already exists in the region (not
  this environment's) is left alone while it is only on by default here: setup saves enable_guardduty=false /
  enable_access_analyzer=false with the environment and plans again. One you set true explicitly (Security Hub and
  Defender are only on when you ask) stops the run before anything changes and names the --var to pass.

EXAMPLES
  cloudseed setup aws
  cloudseed setup gcp -y --env dev --project-id my-proj --allow-ip 203.0.113.7 --auto-approve
  cloudseed setup azure --env dev --subscription-id <id> --state local --dry-run
  cloudseed setup vmware --env lab --var guest_os=debian-12 --var enable_kubernetes=true
  cloudseed setup aws --env prod --name acme --region eu-west-1 --var single_nat_gateway=false
  cloudseed setup aws --env dev --var enable_account_baseline=false     # 2nd env in the same account and region
""",
    "provision": """\
cloudseed provision <cloud> [--env NAME] [--host bastion|vpn|k8s] [--sync-only] [--no-harden] [--no-firewall] [--no-tools]

Runs automatically at the end of `setup` (skip with --no-provision). Copies this repository to the host
over SSH (never your ~/.cloudseed state or keys), installs Ansible there, and applies:
  common     git, jq, tmux, python, timezone, cloudseed + cs on PATH
  hardening  sshd (keys only, no root, strong crypto, AllowUsers), fail2ban, automatic security updates,
             kernel sysctls, auditd, sudo logging, nftables host firewall (default-deny inbound; the SSH sources are
             enforced by the cloud firewall, which `update-ip` changes), banner
  tools      terraform (checksum-verified) and the cloud CLI for this environment; with EKS / GKE / AKS also kubectl
             of the cluster's minor version (sha256-verified). On an AWS bastion: aws eks update-kubeconfig --name
             <cluster> --region <region>, then kubectl. In AWS FIPS mode login shells export AWS_USE_FIPS_ENDPOINT=true
  vpn host   OpenVPN server + PKI, or Tailscale subnet router (playbook ansible/vpn.yml)
  k8s        (vmware) the RKE2 / kubeadm cluster on the private VMs (playbook ansible/kubernetes.yml, run from this machine)

Re-run any time; it is idempotent. Supported images: Amazon Linux 2023, Debian 12, Ubuntu 22.04 / 24.04 (incl. Pro FIPS).

Only what the host needs is copied (ansible/, terraform/, skills/, cloudseed/, bin/, ...), without secrets a checkout
may hold: .env files, *.tfvars, Terraform state and plans, private keys and certificates, kubeconfigs, cloud
credential files, .ssh/ and .kube/ directories, and any cloudseed working directory inside it. A file whose content
is a private key or a service-account key, whatever its name, stops the copy (move it out of the checkout).

--no-harden and --no-firewall also take back what an earlier run installed: --no-firewall removes the nftables host
firewall (VPN hosts and local bastions keep the NAT for the traffic they forward); --no-harden removes the sshd
settings, fail2ban, the audit rules and the kernel/core-dump/sudo settings (the PAM null-password and umask edits and
the automatic security updates stay; kernel settings return to their defaults at the next reboot).

A failed run, or a host that does not answer SSH in time, ends with the whole command to re-run - with the same --host,
--no-harden, --no-firewall, --no-tools and --sync-only flags, so a re-run never hardens a host you provisioned with
--no-harden.

EXAMPLES
  cloudseed provision aws --env dev
  cloudseed provision aws --env dev --host vpn
  cloudseed provision gcp --env dev --sync-only
  cloudseed provision vmware --env lab --host k8s
""",
    "k8s": """\
cloudseed k8s info|kubeconfig|tunnel|untunnel [<cloud>] [--env NAME]

Managed Kubernetes in the private subnets (enable with `--var enable_kubernetes=true` on setup):
  AWS      EKS: private API endpoint, managed node group (AL2023), KMS secret encryption, control-plane logs,
           an access entry for the bastion role only (VPN users reach the API with their own IAM identity: give it
           an access entry), core add-ons (vpc-cni, coredns, kube-proxy). Needs az_count >= 2. external-secrets may
           read only Secrets Manager / SSM names under external_secrets_prefixes (default <name>-<env>/)
  GCP      GKE: private nodes + endpoint, VPC-native, Dataplane V2, Workload Identity, shielded nodes,
           REGULAR channel, managed Prometheus, control-plane logs (API server, scheduler, controller manager);
           Secrets are encrypted at rest with Google-managed keys. kubectl needs gke-gcloud-auth-plugin
  Azure    AKS: private cluster, Azure CNI overlay, NAT-gateway egress, workload identity, control-plane logs in
           Log Analytics; a public API (kubernetes_public_endpoint) also admits the NAT egress IP and the bastion
  VMware   self-managed on private VMs: RKE2 (default) or kubeadm, installed by Ansible from this machine;
           `kubernetes_distro=rke2|kubeadm`, `kubernetes_control_planes`, `kubernetes_workers` (0: the control planes
           run the workloads). The first control plane installs RKE2's stable channel (kubeadm: Kubernetes 1.35)
           and every node added later joins at the version the cluster runs. `kubernetes_version` pins the release
           instead (RKE2: e.g. v1.36.4+rke2r1, installed by every new node; kubeadm: a minor such as 1.35, for a new
           cluster only); it never upgrades a node that is already installed. RKE2's CIS hardening profile is not
           enabled by default: `kubernetes_cis_profile=true` turns it on (RKE2 only; it enforces the restricted Pod
           Security Standard outside the exempt namespaces: RKE2's system ones plus cloudseed-scan, velero,
           local-path-storage, minio and chaos-mesh). `cs platform install` then labels the namespaces of catalog items
           whose pods need more than restricted before installing them - privileged: velero, local-path-provisioner,
           metallb, kube-prometheus-stack, falco, neuvector, kured, chaos-mesh, istio ambient (istio-cni, ztunnel),
           kubescape-operator, trivy-operator, sonarqube; baseline: minio, loki, alloy and similar stacks that run as
           root - and `cs platform info <item>` shows the level

  info        cluster name/endpoint and the kubeconfig command
  kubeconfig  runs the cloud CLI to add the cluster to your kubeconfig (vmware: merges <workdir>/k8s/kubeconfig) and
              switches the current context to it (cs undo takes its entries out and switches back)
  tunnel      writes the per-environment kubeconfig (<workdir>/k8s/kubeconfig) and, for a private cloud API endpoint,
              opens an SSH tunnel to it through the bastion (cs kubectl/helm/k9s do this on demand)
  untunnel    closes that SSH tunnel
Without <cloud> these act on the environment named by --env, else the current one (cs env use), else the only one.

A missing cloud CLI or kubectl is installed only after asking. With -y it is installed only when the run was approved
up front (CLOUDSEED_AUTO_INSTALL=1); otherwise the command stops with exit code 2 and the install command to run first
(cloudseed install gcloud, cloudseed install kubectl, ...).

Variables (clouds): kubernetes_version, kubernetes_node_size, kubernetes_node_count/min/max, kubernetes_public_endpoint
(default false: reach the API through the VPN or an SSH tunnel via the bastion); on GKE the autoscaler never goes below
kubernetes_node_count. Node pools are resized later with `cs node add|remove|scale` (see cloudseed help node).
Variables (vmware): kubernetes_distro, kubernetes_version, kubernetes_cis_profile, kubernetes_control_planes,
kubernetes_workers, kubernetes_cpus/memory_mb/disk_gb (cloudseed help variables vmware).

EXAMPLES
  cloudseed setup aws --env dev --var enable_kubernetes=true --var kubernetes_node_size=t3.large
  cloudseed k8s info aws --env dev
  cloudseed vpn connect aws --env dev && cloudseed k8s kubeconfig aws --env dev && kubectl get nodes
  cloudseed k8s tunnel aws --env dev && cloudseed k8s untunnel aws --env dev
""",
    "vpn": """\
cloudseed vpn status|add-user|users|revoke|connect|disconnect|provision [<cloud>] [--env NAME] [name] [--user NAME]

A VPN host in the public subnet gives your machine a route into the private network
(enable with `--var enable_vpn=true`; choose `--var vpn_type=openvpn|tailscale`). Cloud targets only: vmware has no
VPN (the host reaches the VMs directly), so there `vpn status` and `vpn disconnect` say so and exit 0 without Terraform
or vmrest, and the other subcommands are refused.
Without <cloud> it acts on the environment named by --env, else the current one (cs env use), else the only one.

  openvpn    self-contained: Ansible installs OpenVPN + an Easy-RSA PKI (EC keys, tls-crypt, CRL) on the host.
             add-user issues a client certificate and downloads an inline .ovpn profile to
             <workdir>/vpn/<name>.ovpn (0600). connect starts the OpenVPN client on this machine (a missing
             client is installed after asking; with -y run `cloudseed install openvpn` first or set
             CLOUDSEED_AUTO_INSTALL=1, otherwise it stops with exit code 2), disconnect stops it. Any OpenVPN app can
             import the file. users lists the client certificates with their expiry and which profiles are on this
             machine. Provisioning renews the server certificate by itself within 30 days of its expiry (the client
             profiles stay valid).
  tailscale  the host joins your tailnet as a subnet router advertising the network CIDR. Needs
             TS_AUTHKEY when provisioning; approve the route in the admin console; connect = `tailscale up --accept-routes`.
             add-user, users and revoke are OpenVPN's: with Tailscale, devices are managed in the tailnet.
             Note: Tailscale's coordination plane is a SaaS; traffic itself is end-to-end encrypted.

Certificates (OpenVPN) are valid for 825 days. `vpn status` shows the server certificate's expiry and each local
profile's, and flags one that expires within 30 days: renew the server's with `cloudseed vpn provision <cloud>
--env NAME`, a client's with `cloudseed vpn add-user <cloud> --env NAME <name>` (then import the new profile, or
reconnect).

connect and disconnect run OpenVPN / kill as root through sudo. Without a terminal to type the password into (a web
console job, a scheduler) they use the askpass helper SUDO_ASKPASS (or sudo.conf) names, else `sudo -n`, which only
works with passwordless sudo for openvpn and kill; otherwise they stop with the command to run in a terminal.

EXAMPLES
  cloudseed setup aws --env dev --var enable_vpn=true
  cloudseed vpn add-user aws --env dev alice
  cloudseed vpn connect aws --env dev            # creates a profile for you if none exists
  cloudseed vpn status aws --env dev
  cloudseed vpn revoke aws --env dev alice
  cloudseed vpn disconnect aws --env dev
""",
    "plan": """\
cloudseed plan [<cloud>] [--env NAME]

Re-renders the Terraform root from the saved configuration and shows what `apply` would change.
Never modifies anything.
Without <cloud> it acts on the environment named by --env, else the current one (cs env use), else the only one.

EXAMPLES
  cloudseed plan aws --env dev
  cloudseed plan azure --env prod
""",
    "apply": """\
cloudseed apply <cloud> [--env NAME] [--auto-approve]

Plans and applies the saved configuration. Use it after editing config with `setup`, after a
partial `destroy` (to recreate the removed parts), or to converge drift. As with setup, account-wide settings the
plan would delete are kept and only dropped from the state, and on vmware node VMs the plan deletes are drained and
taken out of the cluster first (see CHANGING AN ENVIRONMENT in `cloudseed help setup`).

EXAMPLES
  cloudseed apply gcp --env staging
  cloudseed apply aws --env dev --auto-approve -y
""",
    "destroy": """\
cloudseed destroy <cloud> [--env NAME] [--select | --target ADDR ...] [--purge-state] [--purge] [--auto-approve]

Destroys everything in the environment, or only what you choose.

  (no flags)          full teardown; shows the destroy plan and asks you to type the env id
  --select            numbered list of modules and resources; pick e.g. 1,3 or 5-9
  --target ADDR       Terraform address to destroy; repeatable / comma-separated
                      (e.g. module.stack.module.bastion, module.stack.module.security_baseline - a module
                      address without [0] covers every instance, on every cloud). vmware has no network or
                      security_baseline module: module.stack.module.bastion | workloads | kubernetes.
                      `--select` lists the exact module and resource addresses of the environment. Terraform also
                      destroys everything that depends on a target: module.stack.module.network takes the bastion
                      host, the VPN host and the Kubernetes cluster with it - the plan and the count list them all,
                      and a warning names every resource outside the targets before you approve
  --purge-state       also delete the remote state bucket / storage account (asked interactively otherwise)
  --purge             also delete the working directory: all of the default ~/.cloudseed/envs/<cloud>-<env>; from a
                      new / empty `setup --workdir` only cloudseed's own files, and the directory itself only when
                      nothing else is left in it (files you added since stay). The audit trail and final inventory
                      are kept in ~/.cloudseed/logs/purged/<cloud>-<env>/; config.json and the SSH keys are kept in the
                      undo journal (~/.cloudseed/undo/, 0700) so `cs undo` can re-create the environment; they are
                      deleted with that entry (undone, dropped with --drop, or pushed out of the history by newer changes)
  --auto-approve      skip confirmations (with -y for fully unattended runs)

Without --auto-approve and without a terminal (or with -y) nothing is destroyed: the destroy plan is shown and the
command exits 3, handy for previews. With an already empty state it lists what would still be removed (leftover VMs, a
vmnet, the state storage, the working directory, a GCP OS Login key cloudseed registered) and exits 3 too - or 0 when
there is nothing left at all, without touching anything. In a terminal a full destroy asks you to type the env id.
Partial destroys keep the configuration; `cloudseed apply` recreates what was removed.

EKS / GKE: before the cluster goes (a full destroy, or a targeted one whose plan deletes the cluster) cloudseed deletes
what Kubernetes created in the cloud: Karpenter NodePools (their instances), Gateways, Ingresses, Services of type
LoadBalancer, StatefulSets with volume claim templates and volumes with reclaim policy Delete. The cluster must be
reachable for that; otherwise cloudseed says what to delete by hand. AKS keeps them in its node resource group.

AWS: the account-wide settings (S3 account public-access block, IAM password policy, the AWS Config service-linked
role) and EBS encryption by default in the region stay in place, no longer managed; CloudTrail (with its bucket),
GuardDuty, Access Analyzer, Security Hub and the Config recorder are deleted. Azure: Defender plans and the Ubuntu Pro FIPS image terms
stay (subscription-wide). GCP: the enabled APIs stay on, and the project-wide logging settings are kept, no longer
managed: the _Default log bucket keeps the retention cloudseed set (log_retention_days; Google never restores an
earlier value, and retention past 30 days is billed - reset: gcloud logging buckets update _Default
--location=global --retention-days=30), and with enable_data_access_audit_logs the allServices Data Access audit config
stays on for the project (other workloads may rely on it). With OS Login, the environment's SSH key is removed from your
Google account when cloudseed registered it and no other environment uses it; otherwise it stays (list and remove it:
gcloud compute os-login ssh-keys list / gcloud compute os-login ssh-keys remove).

vmware: after Terraform, cloudseed sweeps only this environment's leftover VM files (other VMs in the same directory
are listed, never touched); the built-in host-only vmnet (vmnet1) is kept and reused, a dedicated vmnet created for
--cidr is removed from VMware's network config (sudo; otherwise kept and reused). With --purge, vmrest is stopped only
when this cloudseed home configured it, no other VMware environment is left and no VM is running.

EXAMPLES
  cloudseed destroy aws --env dev
  cloudseed destroy aws --env dev --select
  cloudseed destroy gcp --env dev --target module.stack.module.bastion
  cloudseed destroy azure --env dev --purge-state --purge --auto-approve -y     # clean slate
""",
    "env": """\
cloudseed env [show | use <id | a name only one environment has> | clear]

Cluster commands (node, platform, kubectl, helm, k9s) act on "the environment you are in": an explicit
`<cloud> --env NAME`, else the environment chosen with `cs env use`, else the only environment that has a cluster.
With several clusters and nothing chosen you are asked (interactive) or told to pick (non-interactive).

  show   (default) the environments, the current one marked; it takes no id (exit code 2, pointing at cs env use <id>)
  use    makes <id> (as `cs list` shows it, e.g. aws-prod) the current one; a bare name works when exactly one
         environment has it (prod for aws-prod). Without an id a terminal asks; a script gets the list (exit code 2)
  clear  forgets the current one; it takes no id, or only the current one's (anything else exits 2, nothing cleared)

EXAMPLES
  cs env
  cs env use vmware-dev
  cs env clear
""",
    "node": """\
cloudseed node add [--count N] [--role worker|control-plane] [<cloud> | --cloud C] [--env NAME] [--auto-approve]
cloudseed node list [<cloud> | --cloud C] [--env NAME]
cloudseed node remove <node-name> [<cloud> | --cloud C] [--env NAME] [--auto-approve]
cloudseed node scale <cloud> --count N [--min N] [--max N] [--env NAME] [--auto-approve]      (EKS/GKE/AKS)

Scales the cluster of the current environment.
  cloud (EKS/GKE/AKS)  the managed node pool is resized through the cloud API (Terraform only sets its initial size):
                       add raises the pool and its autoscaler minimum and waits for the new nodes to be Ready;
                       remove drains the node and deletes exactly that machine; scale sets the pool size
                       (--count) and the autoscaler limits (--min, default the new count; --max, default unchanged
                       or the count when larger). config.json follows the live pool, so a later apply keeps it -
                       except on GKE, where an apply raises a --min below the count back to the count (the GKE
                       autoscaler never goes below kubernetes_node_count).
  GKE counts           --count, --min, --max and add's increment are PER ZONE. A three-zone pool scaled to --count 2
                       has six total nodes; the preview shows the verified zones and total, and readiness waits for
                       all six. Missing/partial topology, unequal live zone counts and total autoscaler bounds stop
                       before changes. Named remove is supported only for a single-zone pool; use scale for a
                       multi-zone pool so its saved per-zone configuration remains consistent.
  vmware               add creates the VM(s) with Terraform, then Ansible joins them to the cluster automatically
                       (RKE2 agent/server or kubeadm join, depending on the distro). remove drains the node,
                       deletes it from the cluster and, when it is the highest-numbered node, deletes its VM.
                       (vmware nodes are numbered VMs: there is no scale, use add / remove.) add refuses a node whose
                       fixed address would fall in MetalLB's LoadBalancer pool (workers stop at .99 on a /24) and
                       says how many still fit.

EXAMPLES
  cs node add
  cs node add --count 2 --role worker vmware --env dev
  cs node list
  cs node remove acme-dev-wk3
  cs node scale aws --env dev --count 3 --max 6
""",
    "platform": """\
cloudseed platform list|status [--charts] [<cloud> | --cloud C] [--env NAME]
cloudseed platform info <group|item ...>        (a group shows every tool it brings: core, shared, dependencies, extras)
cloudseed platform plan <group|item ...> [--force] [--upgrade] [--version V] [--set k=v]   (what would happen: installs, skips, conflicts, adjusted values)
cloudseed platform install <group|item ...> [--no-wait] [--version V] [--set k=v] [--force] [--upgrade]
                   [--auto-approve] [<cloud> | --cloud C] [--env NAME]
cloudseed platform uninstall <group|item ...> [--force] [--auto-approve] [<cloud> | --cloud C] [--env NAME]
cloudseed platform ui [--auto-approve] | template gitlab-ci   (expose every installed UI · write a CI pipeline template)

A curated catalog of open-source platform components, installed with Helm/kustomize on the current cluster
with values adapted to the target (aws/gcp/azure/vmware) and distro (eks/gke/aks/rke2/kubeadm). Dependencies
are installed first (e.g. cert-manager before the OpenTelemetry operator, MetalLB before ingress on vmware).

GROUPS  (a group installs its core items; extras are installed by name)
  basek8s     metrics-server, cert-manager (Gateway API aware), gateway-api CRDs + envoy-gateway (shared Gateway
              `cloudseed/cloudseed`, wildcard TLS from the cluster CA, private LB per cloud / MetalLB on vmware),
              cert-manager-issuer (the cluster CA), argocd, kube-prometheus-stack, loki (Loki 3) + alloy (log
              collection), opentelemetry-operator, external-secrets, sealed-secrets (+ local-path-provisioner on vmware);
              extras: ingress-nginx (legacy, retired upstream), aws-load-balancer-controller, reloader, kyverno, external-dns
  scaling     keda, vpa (+ metrics-server), goldilocks, cluster-autoscaler (EKS chart; built into GKE/AKS node pools);
              extras: karpenter (aws)
  data        minio, cloudnative-pg, strimzi + a dev Kafka cluster (KRaft), spark-operator + spark-history-server (logs in MinIO),
              trino, starrocks, polaris, airflow; extras: clickhouse-operator
  ai          kuberay, kubeflow-trainer, kserve, jupyterhub, mlflow; extras: kubeflow-pipelines, vllm-stack,
              gpu-operator (clouds), ollama
  agentic     kagent (needs ANTHROPIC_API_KEY or OPENAI_API_KEY: skipped until one is set), kmcp, agentgateway, qdrant;
              extras: langfuse, litellm, open-webui
  finops      opencost (+ kube-prometheus-stack, metrics-server, goldilocks); extras: kube-green, kubecost-cost-analyzer
  devsecops   gitlab, gitlab-runner (skipped until GITLAB_RUNNER_TOKEN is set: cs creds set GITLAB_RUNNER_TOKEN), CI template
              (cs platform template gitlab-ci), neuvector, trivy-operator, argocd, kyverno;
              extras: harbor, artifactory (JFrog OSS), nexus (Sonatype 3), sonarqube
  security    istio (ambient by default; --set mode=sidecar) with strict mTLS, falco (syscall monitoring; its
              Falcosidekick UI through cs platform ui), kyverno + kyverno-policies
              (baseline policies), cert-manager + cert-manager-issuer (cluster CA issuer), external-secrets; extras:
              istio-gateway, kiali, vault, kubescape-operator
  resilience  velero (bucket + identity created in the cloud first; MinIO on local clusters), kured, descheduler;
              drive it with `cs dr`
  chaos       chaos-mesh; extras: litmus; drive it with `cs chaos run`

GATEWAYS AND UIS
  Gateways get PRIVATE load balancers (internal LB in the cloud, MetalLB pool on vmware): reach the cloud ones over
  the VPN (cs vpn connect <cloud> --env NAME) or the bastion; the MetalLB pool on vmware is on the host-only network,
  reachable from this machine directly. Apps attach HTTPRoutes to the shared Gateway;
  `cs platform ui` does that for every known UI (falls back to Ingress if only ingress-nginx exists). When the
  Gateway API stack (or, for Ingress, the cluster CA issuer) is missing, it shows the plan and asks before installing it.
  The UI certificates come from the cluster CA (valid for 10 years; import it once, `cs platform ui` says how). kagent's
  UI is put behind a password (admin / kagent_password in platform/secrets.json).

DUPLICATES AND STEP-OVERS
  Installing several groups never installs a tool twice: items shared by groups and dependencies are resolved once.
  Already-installed releases are skipped (--upgrade re-applies them at cloudseed's pinned version and first refreshes
  the CRDs of charts that keep them in crds/, which helm never upgrades); components a distro
  ships out of the box are skipped too (RKE2: metrics-server; GKE/AKS: metrics-server, cluster-autoscaler). Items whose
  images exist for amd64 only (harbor, litmus, gitlab, kubeflow-pipelines, vllm-stack) are skipped on a cluster whose
  nodes are all arm64 (Apple silicon VMware guests) unless --force. Items with
  the same role conflict and the later one is skipped (opencost vs kubecost-cost-analyzer) unless --force. Charts that
  bundle components another item provides get those parts disabled and the shared one wired in (Kubecost/Kiali -> the
  Prometheus stack, GitLab -> cert-manager and Prometheus, Open WebUI -> Ollama, kagent -> kmcp). Overlapping capabilities
  (envoy-gateway + ingress-nginx, falco + neuvector, vault + external-secrets) are allowed but flagged.
  `cs platform plan ...` shows all of this before touching the cluster. install exits 1 when nothing it was asked for
  can be installed (every named item skipped for a reason: missing token, conflict, architecture, FIPS).

SET VALUES
  A --set key=value (one item at a time) is remembered for that item: a later install or --upgrade applies it again,
  `--set key-` forgets a remembered key, and uninstall forgets the item's values (`cs undo` of the uninstall restores
  them). --set mode=ambient|sidecar picks Istio's mode only when istio is part of the request (named, in a group such
  as security, or a dependency such as kiali or istio-gateway); otherwise mode=... is an ordinary chart value
  (cs platform install minio --set mode=distributed).

POD SECURITY (vmware, RKE2 with kubernetes_cis_profile=true)
  The CIS profile enforces the restricted Pod Security Standard. Before an item whose pods need more is installed,
  each namespace they run in is labelled with the level they need (privileged: e.g. velero, local-path-provisioner,
  metallb, kube-prometheus-stack, falco, neuvector, kured, chaos-mesh, istio ambient, kubescape-operator,
  trivy-operator; baseline: e.g. minio, loki, alloy); a label that is already there is never lowered. The "pod
  security" row of `cs platform info <item>` shows the level.

UNINSTALL
  A group removes its own core items; dependencies are never removed implicitly (cert-manager, gateway-api, metallb and
  local-path are shared). An item still needed by an installed item outside the removal is refused unless --force;
  items that are not installed are reported, and namespaces left empty are deleted. Data survives an uninstall: MinIO's
  volume (PVC minio/minio) and the Polaris database stay (delete them yourself), and cloudnative-pg stays installed
  while Postgres clusters still exist. A CRD chart (kagent-crds, kserve-crd, keda, external-secrets ...) whose CRDs
  still hold objects nothing in the removal made is refused too; with --force those custom resources are saved first
  (in the undo backup) and `cs undo` creates them again after re-installing the chart.

WHERE THE CHARTS COME FROM
  Nothing is vendored: each catalog item records its upstream source (Helm repo + chart, OCI registry, git repo + path,
  kustomize ref, or a manifest URL) and a version pinned per cloudseed release in cloudseed/platform.py; cloudseed pulls
  it at install time with `helm upgrade --install` / `kubectl apply` (--version V overrides it for a single item). `cs platform list --charts` shows the source of every item and
  `cs platform info <item>` shows its chart, version, namespace, dependencies, values per target and notes.
Generated passwords (Grafana, MinIO, ...) and MinIO's access keys (its root user and the users velero and the Spark
history server get: random names, never a well-known one; an older install keeps admin/velero/spark until
`cs platform install <item> --upgrade` rotates it) live in <workdir>/platform/secrets.json (0600). Items needing cloud IAM
(AWS LB controller, cluster-autoscaler, external-secrets, external-dns, EBS CSI) get their identities from cloudseed's
Kubernetes stack automatically (IRSA on EKS, workload identity on GKE/AKS). Items with cloud prerequisites (velero: bucket +
identity; karpenter: controller role, node role + instance profile, EKS access entry, interruption queue, discovery tags)
have them applied through the environment's Terraform stack first (plan + approval as usual). Everything is re-runnable.

EXAMPLES
  cs platform list
  cs platform list --charts
  cs platform info basek8s                    # every tool the group brings
  cs platform plan basek8s finops devsecops   # dry run: installs / skips / conflicts / adjusted values
  cs platform info kube-prometheus-stack
  cs platform install basek8s
  cs platform install data ai
  cs platform install argocd trino --no-wait
  cs platform install kagent --set providers.default=openAI
  cs platform uninstall airflow
  cs platform install security --set mode=sidecar
  cs platform install devsecops --no-wait
  cs platform template gitlab-ci              # writes .gitlab-ci.yml (build, test, trivy scan, release, argocd deploy)
  cs platform ui                              # HTTPRoutes on the shared Gateway for every installed UI + URLs/credentials
  cs platform install finops                  # OpenCost + Prometheus (+ metrics-server, goldilocks) -> cs finops k8s
""",
    "kubectl": """\
cloudseed kubectl [cloud --env NAME] <kubectl args>      (also: cs helm ..., cs k9s)

Runs kubectl / helm / k9s against the current environment's cluster using a kubeconfig kept per environment
(<workdir>/k8s/kubeconfig). A missing tool is installed only after asking; with -y install it first (cloudseed install
kubectl | helm | k9s) or set CLOUDSEED_AUTO_INSTALL=1, otherwise the command stops with exit code 2. For a private
cloud API endpoint without VPN, cloudseed opens an SSH tunnel through the bastion automatically
(`cs k8s untunnel <cloud> --env NAME` closes it). Mutating commands (apply, delete, helm uninstall, ...) take a Velero backup first when
Velero is installed, so `cs undo` can roll them back.

In an agent session the output is redacted line by line and nothing gets a terminal: k9s, kubectl edit and kubectl
exec/attach/run/debug -i/-t are refused, and so are calls that never end on their own (logs -f, get/events -w,
port-forward, proxy): use bounded forms (logs --tail=200, kubectl wait --timeout=120s) or your own terminal.

EXAMPLES
  cs kubectl get nodes
  cs kubectl aws --env prod get pods -A
  cs helm list -A
  cs k9s
""",
    "finops": """\
cloudseed finops estimate | cloud [--days N] | k8s [--window 7d] [--by namespace] | report [--save]   [cloud] [--env NAME]

Three views on money, deterministic and saved for the agent to reason about:
  estimate  what this environment costs per month from cloudseed's own inventory/config (on-demand list prices, offline;
            usage-billed services - GuardDuty, Security Hub, AWS Config, Log Analytics - at a small environment's volume)
  cloud     the actual bill by service from the provider: AWS Cost Explorer, Azure Cost Management
            (GCP needs a BigQuery billing export; cloudseed tells you how)
  k8s       Kubernetes allocation from OpenCost (cs platform install finops) by namespace/controller/pod/label,
            with efficiency so idle requests stand out
  report    all of the above, saved to <workdir>/finops/latest.json

Pair with the agent: cs agentic "look at my finops report and propose the top 5 savings" - the cloudseed-finops
skill knows the report format and the levers (rightsizing via Goldilocks/VPA, KEDA scale-to-zero, kube-green
sleep schedules, node pool sizes via cs node, a single NAT gateway, one shared Gateway instead of a load balancer per
app, dropping an unused VPN host or cluster).
cloudseed creates on-demand / regular nodes only: spot or preemptible capacity is a change made outside cloudseed.

EXAMPLES
  cs finops estimate aws --env dev
  cs finops cloud --days 7
  cs finops k8s --by controller --window 24h
  cs finops report --save
""",
    "managed": """\
cloudseed databricks [--profile NAME] [--env NAME] connect [key=value | --key value ...] | test | status | <databricks CLI args>
cloudseed snowflake  [--profile NAME] [--env NAME] connect [key=value | --key value ...] | test | status | <snow CLI args>

Managed data platforms next to your clusters. cloudseed installs the official CLIs (Databricks CLI, Snowflake CLI;
a missing one after asking - with -y run `cloudseed install databricks|snow` first), keeps one connection profile per
environment (stored 0600 in ~/.cloudseed/managed.json, never handed to agents) and passes every other argument
straight to the CLI with that profile: Databricks gets it as environment variables (DATABRICKS_HOST/TOKEN), `snow`
as a generated 0600 --config-file whose default connection is the profile (not used when you pass -c/--connection,
-x/--temporary-connection or --config-file yourself).

  connect    saves the profile of the current environment (or --profile NAME), then tests it. Values come as
             key=value, --key value or --key=value; unknown keys are refused, anything missing is asked for
             interactively (secrets with hidden input - never put tokens or passwords on the command line):
               databricks  host=https://<workspace>.cloud.databricks.com  (token asked; or `databricks auth login`)
               snowflake   account=<org-acct> user=<u> [role=<r>] [warehouse=<w>] [database=<d>]  (password asked)
             With -y the required ones (databricks host; snowflake account and user) must be given.
  test, CLI  use --profile NAME, else the current environment's profile (cs env use), else the saved 'default' one
  --profile  cloudseed's profile, before or after the subcommand. To hand the vendor CLI its own --profile, start its
             arguments with `--`: cs databricks -- clusters list --profile X
  --env      in front of the subcommand (cs snowflake --env prod test): that environment's profile, by name or
             <cloud>-<env> id; after the subcommand an --env belongs to the vendor CLI

In an agent session the vendor CLI's output is redacted line by line and it gets no terminal: commands that need one -
databricks auth login (a browser sign-in), databricks configure or snow connection add without piped input (snow:
--no-interactive), snow sql without -q/-f (the interactive shell) - are refused with exit code 2 and the command to
run in your own terminal.

EXAMPLES
  cs databricks connect host=https://acme.cloud.databricks.com        # then asks for the token (or use OAuth)
  cs databricks clusters list
  cs databricks jobs list
  cs snowflake connect --account myorg-acct --user me --role SYSADMIN --warehouse COMPUTE_WH
  cs snowflake test --profile prod
  cs snowflake sql -q "select current_version()"
  cs databricks -- clusters list --profile DEFAULT                     # the Databricks CLI's own --profile
""",
    "troubleshoot": """\
cloudseed troubleshoot [<cloud>] [--env NAME] [--last N] [--log]

Deterministic diagnosis - no agent involved. It reads what cloudseed always records in the working directory:
  logs/audit.jsonl        every invocation: when, who, command, exit code, duration, and from where (via: cli, ui
                          for the web console, or the agent: mcp, builtin, claude, ...)
  logs/<ts>-<cmd>.log     full redacted output (cloudseed, terraform, ansible, ssh)
  inventory.json          resources that exist (from terraform state) + change history
and checks the live environment: tools, credentials, bastion port 22 reachability, whether your current public IP
is still allowed, SSH key presence, provisioning status, VMware host/provider/vmrest/images, disk space.
Known error signatures in the log of the failed change are explained with a fix: a failed setup / apply / destroy /
install is diagnosed first, before read-only runs or checks that failed after it; an unreadable local Terraform state
is reported too.
Without <cloud> it acts on the environment named by --env, else the current one (cs env use), else the only one.

EXAMPLES
  cloudseed troubleshoot aws --env dev
  cloudseed troubleshoot vmware --env lab --log
  cloudseed inventory aws --env dev
""",
    "inventory": """\
cloudseed inventory [<cloud>] [--env NAME] [--json] [--last N]

Shows the inventory cloudseed maintains in <workdir>/inventory.json: every managed resource with its
identifiers/addresses, the outputs, and a history of applies, destroys, provisioning runs and VPN user changes.
Kept even on failures; on `destroy --purge` a final copy goes to ~/.cloudseed/logs/purged/<cloud>-<env>/.
Without <cloud> it acts on the environment named by --env, else the current one (cs env use), else the only one.

EXAMPLES
  cloudseed inventory aws --env dev
  cloudseed inventory vmware --env lab --last 30
  cloudseed inventory gcp --env prod --json
""",
    "status": """\
cloudseed status [<cloud>] [--env NAME]

Prints the saved configuration, tags, resource count in state, outputs and the SSH command.
Without <cloud> it acts on the environment named by --env, else the current one (cs env use), else the only one.

EXAMPLES
  cloudseed status aws --env dev
  cloudseed status gcp
  cloudseed status                     # the current (or only) environment
""",
    "output": """\
cloudseed output [<cloud>] [--env NAME] [--json]

Prints the stack outputs (bastion IP, subnet IDs, security group / tag for workloads, ...).
Without <cloud> it acts on the environment named by --env, else the current one (cs env use), else the only one.
See `cloudseed help outputs <cloud>` for the meaning of each output.

EXAMPLES
  cloudseed output aws --env dev
  cloudseed output aws --env dev --json | jq -r .private_subnet_ids[]
""",
    "ssh": """\
cloudseed ssh [<cloud>] [--env NAME] [-- extra ssh args]

Opens an SSH session to the bastion using the generated (or configured) private key.
Extra arguments go to ssh, e.g. port forwards.
Without <cloud> it acts on the environment named by --env, else the current one (cs env use), else the only one.

EXAMPLES
  cloudseed ssh aws --env dev
  cloudseed ssh aws --env dev -- -L 5432:10.0.16.10:5432
""",
    "update-ip": """\
cloudseed update-ip <cloud> [--env NAME] [--allow-ip IP ...] [--auto-approve]

Re-detects your public IP (or takes --allow-ip: IPv4 only, nothing wider than a /8, two /8s at most, a range as its
network - 203.0.113.0/24, or 203.0.113.7/32 for one address; 203.0.113.7/24 is refused) and updates the SSH rule of the
cloud firewall (security group / VPC firewall / NSG). Use it whenever your ISP / VPN changes your address and SSH
stops working. Only the SSH-source changes are applied: other pending changes in the plan are left alone (review them
with `cloudseed plan`), and config.json keeps the old sources until the apply worked. Afterwards it checks SSH to the
bastion and, when it still does not answer (a host provisioned by an older version pins the old address in its own
nftables), prints the recovery commands. When SSH works, it also lifts a fail2ban ban of the new address on the
bastion (and a provisioned VPN host) and has fail2ban ignore it; the next `cloudseed provision` writes it into the
jail for good.
Cloud targets only: on vmware it explains why it does not apply (the VMs are on a private VMware network) and exits 0.

EXAMPLES
  cloudseed update-ip aws --env dev
  cloudseed update-ip azure --env dev --allow-ip 198.51.100.4,203.0.113.0/24 --auto-approve
""",
    "list": """\
cloudseed list

Lists every environment with name, region, state location, bastion IP and last update.

EXAMPLES
  cloudseed list
""",
    "doctor": """\
cloudseed doctor [cloud]

Checks Terraform, ssh-keygen and the cloud CLIs (optional) and lists the tools no cloud needs (kubectl, helm, the VPN
clients ...) once, under "Common tools"; shows versions, the runtime
preference, container engines, and whether credentials were detected for each cloud. With a cloud it also checks the
credentials live (when that cloud's CLI is installed) and, when something keeps that cloud from working, ends with one
verdict line naming it ("... is not ready: ...") and exits 1. The overview (no cloud) always exits 0.

EXAMPLES
  cloudseed doctor
  cloudseed doctor aws
""",
    "deps": """\
cloudseed deps status
cloudseed deps install <tool...|all>          (terraform aws gcloud az kubectl helm k9s ...; all = terraform aws gcloud az)
cloudseed deps image [--engine docker|podman] [--rebuild]
cloudseed deps bundle
cloudseed deps runtime <auto|local|container> [--engine ...]

Three ways to satisfy dependencies - you pick:
  install   Homebrew when available, otherwise official releases into ~/.cloudseed/bin (SHA256-verified for terraform,
            kubectl, helm, go, k9s and databricks; aws / gcloud from the vendors' installers over HTTPS; az / snow with pip,
            which needs Python 3.10+)
  image     build the all-in-one container image (Terraform + aws + gcloud + az + kubectl + helm) with Docker or Podman;
            then run any command with --runtime container (or set it as default with `deps runtime container`)
  bundle    build dist/cloudseed-<os>-<arch>: one binary with the CLI, all Terraform modules and Terraform itself

When a required tool is missing, `setup` offers these choices interactively. `cloudseed install <what>` installs the
same tools plus groups (cloud, vmware, vpn, kubernetes), skills, agents and the VMware provider (see
`cloudseed help install`).

EXAMPLES
  cloudseed deps install terraform
  cloudseed deps install all
  cloudseed deps image --engine podman
  cloudseed deps runtime container
""",
    "enable": """\
cloudseed enable agentic [--agent builtin|claude|codex|gemini|grok]
cloudseed enable headliner | mcp | ui [--port N] [--no-open]

  agentic     turn on agentic mode: picks the agent (built-in by default, or your logged-in Claude Code
              when no API key is set), installs its CLI/SDK and skills if needed. Afterwards
              `cloudseed agentic "<task>"` (or `cs agentic "..."`) hands tasks to the agent.
              Deterministic commands keep working unchanged.
  headliner   (default on) prepend a compact, secret-free research brief to every agent task so the
              agent does not burn tokens exploring.
  mcp         allow the local MCP server to run (the full deployment with client wiring is `cloudseed setup mcp`)
  ui          start the local web console as a user service and open it (same as `cloudseed ui start`);
              it listens on --port (default 7434); --no-open starts it without opening the browser

EXAMPLES
  cloudseed enable agentic
  cloudseed enable agentic --agent claude
  cloudseed enable headliner
  cloudseed enable ui --port 7440
  cloudseed enable ui --no-open         # start the console without opening a browser
""",
    "mcp": """\
cloudseed setup mcp [--transport http|stdio] [--client all|none|<name>...] [--client-transport http|stdio]
                [--yes-clients] [--host 127.0.0.1] [--port N] [--[no-]auth] [--[no-]service] [--rotate-token]
cloudseed mcp status | guide | connect <client|all> [--transport http|stdio] | disconnect <client|all>
cloudseed mcp tools | config | test [--http] | serve [--http] [--host H] [--port N] | start | stop | restart
cloudseed mcp logs [--lines N | -n N] | token [--rotate] | uninstall [--auto-approve]
cloudseed status mcp · cloudseed destroy mcp   (aliases of mcp status / mcp uninstall)

cloudseed as a Model Context Protocol server: every feature is a tool any MCP client can call - Claude Code, Claude
Desktop, Codex, Cursor, Windsurf, Gemini CLI, VS Code, LangGraph, ... (48 tools; `cs mcp tools` lists them):
  discover          list, doctor, status, output, inventory, env
  build & change    setup (plan / apply / dry run), plan, apply, update-ip, provision, install
  kubernetes        k8s, node, platform, kubectl, helm
  access            ssh, vpn, managed (databricks / snowflake)
  cost & docs       finops, troubleshoot, explain, help, skill
  resilience        dr (backup / restore / drill), chaos (experiments with verdicts), scan (CIS / STIG / CVEs /
                    cloud / FIPS / local Well-Architected assessments)
  undo & teardown   undo (revert the last environment action), destroy
Shared operational tools (replace the shown hyphens with underscores after cloudseed_ in the tool name):
  ops-credentials-backend, ops-acceptance, ops-release-verify
  ops-expiry-plan, ops-expiry-cleanup, ops-health
  ops-network, ops-profile, ops-spec-export
  ops-spec-validate, ops-spec-diff, ops-spec-import
  ops-policy-check, ops-drift, ops-upgrade-plan
  ops-upgrade-apply, ops-recovery-plan, ops-recovery-test
plus resources (cloudseed://environments, cloudseed://skills/<name>), the resource template cloudseed://explain/{query}
(how anything works, as JSON - the same data as cloudseed_explain with format=json and `cs explain --json`) and prompts
(create-environment, review-environment, troubleshoot, teardown).

  --client-transport   setup: how the connected clients reach the server (default: http when the service is deployed)
  --yes-clients        setup -y: connect every detected client without asking
  --host / --port      bind address (loopback only) and TCP port (default 7433, or the next free one)
  --no-auth            setup / serve --http: no bearer token, only for a client that cannot send headers (any local
                       process can then call every tool). A setup re-run keeps it; at a terminal it offers the token
                       back; --rotate-token requires a token again
  --no-service         setup: a detached background process instead of the launchd/systemd login service. A setup
                       re-run keeps it; at a terminal it offers the login service back
  --rotate-token       setup: issue a new bearer token (after --no-auth: the server requires a token again)
  --auto-approve       uninstall without asking
  --auth / --service   setup: the bearer token again after --no-auth (a new one when none is left) / the login
                       service again after --no-service - without a terminal too (a script, the web console)

  connect / disconnect take client names or `all`; without names a terminal asks about each client (a script gets
  the list to pass). A client that is already connected keeps its transport unless --transport says otherwise; a new
  one gets http when the HTTP server is deployed, else stdio. `mcp connect` on a home where MCP was never set up
  enables it (stdio: the client launches `cloudseed mcp serve`); after `disable mcp` or `destroy mcp` it connects the
  client but only warns that MCP is off. `mcp start` and `mcp restart` refuse while MCP is disabled (cs enable mcp).
  `mcp token --rotate` needs the HTTP deployment (stdio has no token); clients connected over HTTP are updated with
  the new token automatically.

SETUP MCP DEPLOYS IT
  1. starts a local Streamable-HTTP server on http://127.0.0.1:7433/mcp (legacy SSE at /sse for older clients) as a
     launchd (macOS) / systemd --user (Linux) service that starts at login, protected by a bearer token stored 0600
     under ~/.cloudseed/mcp/token. `--transport stdio` skips the service: clients launch `cloudseed mcp serve` themselves.
  2. asks which detected clients to connect (or --client all | none | claude-code codex ...) and writes their config:
     Claude Code (`claude mcp add -s user`), Claude Desktop (claude_desktop_config.json, stdio - the app only launches
     commands), Codex (~/.codex/config.toml), Cursor (~/.cursor/mcp.json), Windsurf, Gemini CLI (~/.gemini/settings.json),
     VS Code (User/mcp.json). Other clients: `cs mcp config` prints snippets for both transports.
  3. prints the guide - server details, how to verify in each client, what to ask, the safety model, how to turn it off -
     and saves it to ~/.cloudseed/mcp/CONNECT.md (`cs mcp guide` prints it again).

SECURE BY DEFAULT
  - loopback only (127.0.0.1); the Origin header is validated (no DNS rebinding); every request needs the bearer token
    (401 otherwise) unless the server was deployed with --no-auth (then any local process can call it; cs mcp status
    says so). stdio has no port at all. Never expose the server publicly.
  - refuses to start until enabled (`setup mcp` / `enable mcp`); `disable mcp` stops it.
  - tools run cloudseed as a child with the credential session broker: the client never sees secrets; output is redacted;
    Terraform state and credential files are not exposed as resources.
  - every call is checked against the tool's input schema first (types, enums, required and unknown arguments; the
    string "false" is not a yes).
  - destructive tools carry destructiveHint and refuse to run unless the call has confirm=true: setup with apply, apply,
    destroy, update-ip, provision, node add/remove/scale, platform install/uninstall/ui, vpn add-user/revoke/provision,
    ssh commands, install, mutating kubectl/helm, databricks/snowflake commands other than status/test/list/get/describe,
    scan (every kind except architecture, fips and reports: they run cluster jobs or Ansible, or install scanners), dr
    backup/restore/schedule/test, chaos run/stop, undo (--drop included). Reading Kubernetes Secrets (kubectl get
    secret, get --raw on secrets) or helm release values (helm get values|all|manifest|hooks, helm status -o json|yaml)
    needs confirm=true too: they can print passwords that redaction cannot always recognise.
  - meta commands (agentic, enable/disable, use, model, mcp, ui, creds) are not tools, and cloudseed_undo only reverts
    environment actions: global actions (MCP, UI, credential and agent settings) are undone by you only, with
    `cs undo --global` or the web console - an agent's call for one is refused.
  - long calls: Codex and Gemini CLI entries get a 1-hour tool timeout; start Claude Code with MCP_TOOL_TIMEOUT=3600000
    if setup/apply calls time out. Cancelling a call in the client interrupts the command (Terraform stops cleanly).
  - a launchd/systemd service sees credential FILES (~/.aws, gcloud ADC, az login) but not variables exported in a
    shell; for env-var credentials connect that client over stdio (`cs mcp connect <client> --transport stdio`).

EXAMPLES
  cs setup mcp                          # deploy + pick clients interactively + guide
  cs setup mcp -y --client all          # non-interactive: connect every detected client
  cs setup mcp --transport stdio --client claude-desktop
  cs mcp connect codex cursor           # add clients later (new ones: http when deployed, else stdio)
  cs mcp status                         # health, service, which clients are connected
  cs mcp test --http                    # protocol round-trip against the running server
  cs mcp token --rotate                 # new bearer token + restart; HTTP-connected clients are updated automatically
  cs destroy mcp                        # stop, remove the service, the token and every client entry
""",
    "ui": """\
cloudseed enable ui [--port N] [--no-open]   start the local web console (launchd / systemd user service) and open it
cloudseed ui [open | start [--port N] [--no-open] | status | stop | restart | logs [--lines N | -n N] | token [--rotate]]
cloudseed ui serve [--host 127.0.0.1] [--port N]      run the console in the foreground (what the service runs)
cloudseed disable ui

A branded console at http://127.0.0.1:7434/ (loopback only, token in the link and kept only in the browser tab - no cookie, no CDN, no telemetry) where every
cloudseed capability is a form and a button: create/change/destroy environments (wizard built from each cloud's questions),
the whole platform catalog (install/plan/uninstall groups or single items, expose UIs, kubectl/helm, nodes), DR drills,
chaos suites, every scan, reports viewer, agents (enable/disable, pick agent + model, run tasks, skills), the MCP server
(deploy, connect clients, guide), credentials vault, help. Every action runs the same `cloudseed ...` command the CLI runs,
streams its output live into the console drawer, and is logged in the audit trail. Destructive actions need a tick.

Credentials entered in the UI go to the local vault (~/.cloudseed/credentials.json, 0600) and are injected into cloudseed
processes only; shell variables always win. `cs creds` manages the same vault from the terminal.

A "?" beside each view's title, wizard cloud, field and question, environment card and chip, platform group and item,
resilience card, report, agent and MCP control, credentials group, action card and dialog explains that thing in place;
hovering shows a one-line summary and its `cs explain` command, clicking opens the Explain panel with the page that
`cs explain <thing>` prints (headings, bullets, copyable commands; a Terminal switch shows the exact CLI text; related
pages are links and Back returns; Open in Help shows it full width). ⌘K lists an "Explain: <name>" entry for everything
explainable and the Help page has an explain search. The panel reads GET /api/explain - documentation only, no job and
no audit entry (cs help explain).

  open      (default) open the console in the browser, starting it if needed
  start     start the user service; --no-open skips the browser, --port picks the port (default 7434)
  logs      the last --lines/-n lines of ~/.cloudseed/ui/server.log

KEYBOARD (also listed on the console's Help page)
  ⌘K / Ctrl+K   search actions, environments, the catalog and explanations
  ?             explain the page you are on
  1 … 0         go to a view, in the order of the sidebar
  `             show or hide Activity
  ⌘B / Ctrl+B   collapse the sidebar (the menu on a small screen)
  Esc           close the explanation, a dialog or the palette
  Alt+←         back, in the explanation

EXAMPLES
  cs enable ui                # start + open
  cs ui                       # open again (starts it if needed)
  cs ui start --no-open       # start without opening a browser
  cs ui token                 # the link with the token
  cs creds set AWS_PROFILE=prod ANTHROPIC_API_KEY     # the API key is asked with hidden input
""",
    "undo": """\
cloudseed undo [<cloud> --env NAME] [--auto-approve]      undo the newest action of that environment (no filter: the newest
                                                          anywhere; a cloud or --env alone only narrows the choice - it asks,
                                                          or stops, when several environments match)
cloudseed undo --global                                   the newest global action (settings, agents, MCP, UI, credentials)
cloudseed undo --list [<cloud>] [--env NAME]              the history (15 undo points per environment and 15 global; times in UTC)
cloudseed undo --id ID                                    that entry (from --list); refused while a newer one in its scope is left
cloudseed undo [...] --drop                               discard the entry without undoing it (a step that can never succeed)

Every state-changing action leaves a journal entry (~/.cloudseed/undo.json) with everything needed to revert it:
  setup / apply changes, update-ip                                         -> the previous config.json is restored and the
                                                                              stack re-applied (Terraform converges back; local
                                                                              cluster nodes it deletes are drained first)
  node add|remove|scale on EKS/GKE/AKS                                     -> the pool is scaled back to its previous size and
                                                                              autoscaler limits (cs node scale)
  cloud prerequisites (platform install)                                   -> the same, except that Velero's bucket and
                                                                              identity are kept (they hold the backups)
  vmware node add                                                          -> the new nodes are removed with cs node remove
                                                                              (drained, taken out of etcd, VM deleted)
  vmware node remove                                                       -> the highest-numbered node is re-created and
                                                                              joins again; another node (VM kept) or a node
                                                                              that is not the environment's VM: how to rejoin it
  the first setup of an environment                                        -> the environment is destroyed (workdir kept)
  platform install / uninstall                                             -> the same items are uninstalled / re-installed
  vpn add-user                                                             -> the client certificate is revoked
  dr backup / dr schedule                                                  -> the backup / schedule is deleted
  destroy --target / apply                                                 -> apply / destroy the resources apply created
  destroy (full, even --purge)                                             -> config + keys were saved: setup re-creates it (new hosts)
  provision                                                                -> previous provisioning flags, or a fresh unprovisioned host
  ssh <remote command>                                                     -> re-provision (restores every managed host setting)
  dr restore, helm uninstall, other mutating kubectl                       -> a Velero backup taken right before is restored (Velero needed);
                                                                              objects and namespaces the change created are
                                                                              deleted first
  kubectl create/apply of new objects, node label/annotate, cordon/drain   -> exactly those objects are deleted / the previous
                                                                              values come back / uncordon
  helm install / upgrade / rollback                                        -> helm uninstall / rollback to the previous revision
  vpn revoke / connect / disconnect                                        -> re-issue / disconnect / connect
  chaos run, dr test, scans, finops reports                                -> stop experiments / delete the kept drill namespace
                                                                              and backup / delete the reports
                                                                              (only their own files: a folder later runs also
                                                                              wrote to is kept)
  k8s kubeconfig                                                           -> the contexts it merged are taken out again (contexts
                                                                              other tools added since stay; the previous current
                                                                              context comes back)
  platform template, mcp/ui token rotate                                   -> the previous file is put back; a file you changed
                                                                              since is kept as <file>.cloudseed-undo-<time>
  install / deps install / skill install                                   -> files placed under ~/.cloudseed/bin or the skills dir are removed
                                                                              (skills they replaced are put back)
  env use, use <agent>, model, deps runtime                                -> the settings keys that command changed get their
                                                                              previous values (other settings stay)
  mcp setup/connect/disconnect/stop, enable/disable <feature>, creds       -> the opposite command / previous values (creds
                                                                              unset|clear keep a copy of what they removed)
A kubectl or helm call that failed part-way keeps its undo point, marked '(failed part-way)'. An undo point of the
whole cluster (a change not limited to namespaces) holds objects only: the velero and minio namespaces and pod volumes
are left out.
Read-only commands (status, list, output, plan, help …) change nothing and leave no entry.

Fifteen real undo points are kept per environment (and fifteen for global actions), at most five of one kind: a burst
of one kind of change (ten kubectl edits) only pushes out older changes of that kind, never the environment's creation,
its platform installs or backups. Reports, scans, drills, chaos runs and 'info' entries (e.g. kubectl/helm changes
without Velero, which only say how to revert by hand) are minor: they have five slots of their own and never push a real
undo point out. A setup/apply undo rewrites config.json only once the re-apply worked. Account/subscription-wide
settings its plan would delete are only dropped from the state (as a destroy does), and Velero's bucket is never removed
by an undo (it holds the backups).

The same journal serves the CLI, the agents (skill), the MCP server (cloudseed_undo) and the web console (↶ Undo).
Global entries (settings, agents, MCP, UI, credentials) are undone by you only: when CLOUDSEED_AGENT is set (the MCP
server, the built-in agent, external agents) `cs undo` skips them and `cs undo --global` is refused.
Each undo asks for approval like the action it reverts (--auto-approve to skip). When the undo points are used up, or an
undo cannot converge, destroy the environment and start over: cs destroy <cloud> --env NAME.

Work Velero still runs is never raced: the undo of a `dr restore --no-wait` (or of one interrupted while waiting) and of
a `dr test --keep` whose backup is still being written is refused, entry kept, until Velero has finished. Undoing a
purge puts the environment back into its own working directory (a custom --workdir is registered again) and makes it
the current environment again when it was. `cs undo --list` shows the times in UTC.

EXAMPLES
  cs undo --list
  cs undo aws --env dev               # e.g. removes the Kubernetes cluster that the last `setup --var enable_kubernetes=true` added
  cs undo                             # newest action anywhere (e.g. uninstall the platform group you just installed)
  cs undo --global                    # e.g. put back the agent / model / credential you just changed
  cs undo --id 20260101-120000-a1b2c3 --drop   # skip a step that can never succeed
""",
    "creds": """\
cloudseed creds [list] | set KEY=VALUE ... | set KEY (prompts, hidden) | unset KEY ... [--forget] | clear [--forget]

Local credential vault used by every cloudseed command (CLI, UI, MCP): AWS keys/profile, a GCP service-account key,
Azure service principal, Anthropic/OpenAI/Gemini/Grok API keys, Ubuntu Pro token, Tailscale auth key, GitLab runner
token, Databricks/Snowflake, or any custom variable. For GCP the simplest is the key file's path:
GOOGLE_APPLICATION_CREDENTIALS=/path/key.json. GOOGLE_CREDENTIALS takes the file's JSON contents instead (never a
path): paste them at the hidden prompt of `cs creds set GOOGLE_CREDENTIALS`. Stored in ~/.cloudseed/credentials.json (0600), never printed (masked),
injected as environment variables at start; variables already exported in the shell take precedence. Agents never see
them: they are stripped by the session broker like every other secret.

For secrets use `set KEY` without a value: it prompts with hidden input, so the value never reaches your shell history
or the process list. It needs a terminal - without one it stops with exit code 2 and changes nothing (it never deletes
anything; `unset` does). KEY=VALUE is fine for non-secret settings (profiles, project ids, paths); its value is masked in
the audit log whatever the name.
Names: letters, digits and _ (stored upper case); names that change how programs start, which code they load, which
files or servers they trust, or where they send requests (PATH, HOME, LD_*/DYLD_*, PYTHON*, ANSIBLE_*, OPENSSL_*,
NODE_*, GIT_*, *_CONFIG, *_BASE_URL, *_ENDPOINT*, HTTP(S)_PROXY, TF_LOG*, CLOUDSEED_*, ...) are refused: set those in
your shell if you really need them. Path values (GOOGLE_APPLICATION_CREDENTIALS)
are stored absolute, with ~ expanded. `list` shows secrets masked (•••••••• plus the last 4 characters of long ones),
text and path values in full, and 'from shell' for a variable only your shell exports (a shell variable always wins).
`cs undo --global` reverts set, unset and clear - an overwritten value comes back. unset/clear keep a copy of the removed
values in the undo journal (0600) until newer global changes push that entry out of the history; --forget keeps no copy
and drops the older ones.

EXAMPLES
  cs creds set AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY             # both prompt (hidden input)
  cs creds set AWS_PROFILE=prod GOOGLE_APPLICATION_CREDENTIALS=~/keys/proj.json
  cs creds list
  cs creds clear --forget                                          # empty the vault; nothing is kept for undo
""",
    "chaos": """\
cloudseed chaos run [basic|network|stress|full | <experiment>...] [--suite S] [--target ns/deploy[:port]]
                [--duration 45s] [--replicas 3] [--keep] [--auto-approve] [<cloud> | --cloud C] [--env NAME]
cloudseed chaos list | status | stop | report   [<cloud> | --cloud C] [--env NAME]

Automated chaos engineering on the current cluster with Chaos Mesh (installed on first use: asked on a terminal, or
with --auto-approve; `cs undo` removes it again). `run` deploys a canary
workload (3 replicas, PDB, Service, probe pod) - or targets one of your Deployments with --target - and executes the
experiments one by one. Each experiment has a steady-state hypothesis: availability is sampled from the probe pod while
the fault is injected, the fault is lifted, recovery to full availability is timed, and the verdict is PASS when both the
availability floor and the recovery bound hold. A fault Chaos Mesh never injected is an ERROR, never a PASS. The run's
verdict is PASS only when every experiment ran and passed, FAIL when one failed or errored, otherwise INCONCLUSIVE; the
exit code is 0 only for PASS. Results are printed as a table and saved to <workdir>/chaos/report-<run>.json/.md.

  basic    pod-kill, pod-failure, container-kill                (a Deployment must replace / restart pods)
  network  network-delay, network-loss, network-partition, dns-error   (requests survive latency and loss; outages recover)
  stress   cpu-stress, memory-stress, time-skew                 (pods keep serving under pressure)
  full     all of the above

  --suite S          the suite to run when no suite/experiment is named (default basic)
  --duration T       fault time per experiment: 45, 45s or 2m (15s..1h, default 45s)
  --replicas N       canary replicas, 2..20 (default 3; not used with --target). Bad values stop with exit code 2
                     before anything touches the cluster
  --keep             keep the canary namespace afterwards (cs chaos stop removes it)
  --auto-approve     do not ask before injecting faults into your own workload (--target), and install Chaos Mesh
                     when it is missing (its daemon runs privileged on every node)

EXAMPLES
  cs chaos run                               # basic suite against the canary
  cs chaos run full --duration 2m
  cs chaos run network-loss cpu-stress vmware --env lab
  cs chaos run basic --target shop/api:8080  # your workload (pods WILL be killed; asks first)
  cs chaos report                            # the last verdict table
""",
    "dr": """\
cloudseed dr status|backup|restore|backups|schedule|test [name] [<cloud> --env NAME]
cloudseed dr backup [name] [--namespaces a,b] [--no-wait] · dr restore <backup> [--no-wait]
cloudseed dr schedule <name> --cron "0 2 * * *" [--ttl 720h] · dr test [--keep] [--[no-]volume]
cloudseed dr describe backup|restore <name> [--details] · dr logs backup|restore <name>
             (every dr command also takes [--auto-approve]; --cloud C names the target when a word could be read
             as a backup name)

Disaster recovery with Velero. `cs platform install velero` (or the first `cs dr` command) deploys it after creating what
it needs in your cloud through the environment's own Terraform stack: a versioned, encrypted, private bucket (S3 / GCS /
Azure Blob) and a least-privilege identity for the velero service account (IRSA / GKE Workload Identity / Azure workload
identity + snapshot role). On local clusters backups go to MinIO, and the local-path StorageClass creates 'local'
volumes, which the node agent can back up. Volumes are backed up by the node agent (file-system backup).
`cs dr status` and `cs dr backups` read Velero's objects with kubectl and need no velero CLI. The other commands use
the velero CLI of the server's version, fetched into ~/.cloudseed/bin only on your own run: on a terminal, or with -y
after --auto-approve (or CLOUDSEED_AUTO_INSTALL=1) - never in an agent session, which stops with the command to run.
`cs dr describe` and `cs dr logs` show Velero's own view of one backup or restore (its objects, volumes, errors and
log) with the environment's kubeconfig; without a velero CLI here they run it in the velero pod.
Backup, restore and schedule names are Kubernetes names (RFC 1123: lower-case letters, digits, '-' and '.').

`cs dr test` is the automated drill: create a sample workload (Deployment, ConfigMap, Secret, Service, a 1Gi volume when a
default StorageClass exists, with a random file written on it) -> back it up -> delete the namespace -> restore -> verify
every object and that the random file came back (the backup and restore must show Completed PodVolumeBackups /
PodVolumeRestores) -> print PASS/FAIL with the measured restore time; exit code 1 on FAIL.
Report: <workdir>/dr/drill-<run>.json/.md. Afterwards the drill deletes its namespace and backup (a backup Velero is
still writing expires by itself after 24h); --keep leaves both for inspection: the drill names them and prints the
commands that remove them (or: cs undo), and the kept backup has no drill TTL, so Velero keeps it for its default 30 days.
On local clusters the backups live in the in-cluster MinIO, which only answers inside the cluster: `cs dr describe|logs`
then run velero in the velero pod. Other velero commands cloudseed suggests (deleting a backup) run there too, so no
velero CLI on PATH is needed: cs kubectl <cloud> --env NAME -n velero exec svc/velero -c velero -- /velero backup
delete <name> --confirm (cloudseed prints the exact command where it is needed; svc/velero, not deploy/velero, whose
selector also matches the node-agent pods).

  --cron          schedule: a cron expression evaluated by Velero in UTC (default "0 2 * * *" = 02:00 UTC nightly)
  --no-wait       backup/restore: return right away instead of waiting for Velero to finish
  --ttl           schedule: how long Velero keeps each backup, a Go duration (720h = 30 days, the default; 30d is
                  taken as 720h)
  --[no-]volume   test: --no-volume skips the volume; --volume forces it and needs a default StorageClass or an
                  Available unclassed PersistentVolume of 1Gi+ (default: on when a default StorageClass exists)
  --keep          test: keep the drill namespace and its backup (kept for Velero's default 30 days; without --keep the
                  backup is deleted, at the latest by Velero after 24h)
  --details       describe: also list every object and volume the backup or restore holds
  <cloud>, --cloud C   the environment's target with --env (the current environment otherwise, see `cs env`); a word
                  that is a cloud key is the target, unless --cloud is given (then it is taken as the name)
  --auto-approve  install Velero (and its bucket + identity) and restore without asking

EXAMPLES
  cs dr test                                 # prove backups can be restored
  cs dr backup --namespaces shop,payments
  cs dr schedule nightly --cron "0 2 * * *" --ttl 720h        # 02:00 UTC every night
  cs dr restore cloudseed-20260922-011500 --namespaces shop
  cs dr describe backup cloudseed-20260922-011500 --details
  cs dr status aws --env prod
  cs dr backup before-upgrade vmware --env lab
""",
    "scan": """\
cloudseed scan cis | kube [--framework nsa,mitre,cis-v1.10.0] | images                 (current cluster)
cloudseed scan host [<cloud> --env NAME] [--host bastion,vpn,k8s] [--profile cis|stig]  (OpenSCAP on the hosts)
cloudseed scan stig [<cloud> --env NAME] [--host bastion,vpn,k8s]                       (hosts: DISA STIG; EKS: Kubernetes STIG)
cloudseed scan cloud [<cloud> --env NAME] [--framework cis_4.0_aws]                     (account / project / subscription)
cloudseed scan fips [<cloud> --env NAME]                                                (FIPS 140 verification)
cloudseed scan architecture [<cloud> --env NAME] [--profile production|lab] [--max-age-days 30] [--json]
cloudseed scan all [<cloud> --env NAME] · cloudseed scan reports [--last N]

  cis     CIS Kubernetes Benchmark with kube-bench: the right profile per distro (eks-1.8.0, gke-1.9.0, aks-1.8, rke2-cis-1.9,
          auto-detected for kubeadm); control-plane + node checks where nodes are yours. PASS/FAIL/WARN counts, failing controls
          with remediation. The policies checks (RBAC, service accounts, network policies) run with a temporary read-only
          ClusterRole (no secrets), removed when the scan ends. The "default namespace should not be used" checks (EKS
          4.5.2, GKE 4.6.4, AKS 4.6.3) are decided by cloudseed, listing that namespace with the environment's own
          credentials. On a VMware RKE2 cluster whose CIS profile is off, failures come with the next step:
          cs setup vmware --env NAME --var kubernetes_cis_profile=true, then cs provision vmware --env NAME --host k8s.
  kube    kubescape posture scan: NSA + MITRE ATT&CK frameworks by default (add cis-v1.10.0, soc2 ...); compliance score and
          failing controls by severity. Continuous variant: cs platform install kubescape-operator.
  images  vulnerabilities in running workloads: trivy-operator reports when installed, else a one-off `trivy k8s` scan.
  host    OpenSCAP + SCAP Security Guide on every SSH-reachable host (bastion, VPN, local Kubernetes nodes): CIS level 1/2
          server profile (or --profile stig); Ubuntu 22.04 through the Ubuntu Security Guide (needs Ubuntu Pro). Score, failed
          rules, HTML report per host under <workdir>/scans/openscap-<run>/. A host with no content for the profile is n/a.
  stig    DISA STIG: hosts with a stig profile (Ubuntu 24.04, Ubuntu 22.04 with Ubuntu Pro, RHEL 8/9; not AL2023 or Debian 12,
          which report n/a - the default AWS/GCP bastions); on EKS also kube-bench's
          eks-stig-kubernetes benchmark. Managed GKE/AKS/EKS nodes are not SSH-reachable (provider-hardened) - use `cis` there.
  cloud   prowler against the account: newest CIS benchmark for the provider by default (--framework for another id).
          In an AWS FIPS environment only its region is audited, through the FIPS endpoints (the summary says so).
  fips    verifies FIPS mode end to end: config, SSH key type, kernel fips_enabled and sshd/OpenSSL algorithms on every host,
          FIPS endpoints / node images, RKE2 build, TLS policy on the shared Gateway, FIPS capability of every installed item
          (crypto-restricted ones - cert-manager, sealed-secrets, velero, cloudnative-pg - are reported as not
          FIPS-validated). In AWS FIPS environments also, on the live cluster: AWS_USE_FIPS_ENDPOINT on the AWS
          controllers, Velero's s3-fips endpoint, Karpenter EC2NodeClass AMIs and '-fips' Bottlerocket node images.
          On an environment created without fips_mode the verdict is N/A.
  architecture  Well-Architected assessment of saved configuration and local evidence. AWS/GCP: six pillars;
          Azure: five pillars plus separate sustainability guidance; VMware: local infrastructure best practices.
          Defaults: --profile production, --max-age-days 30. Lab relaxes production availability expectations;
          it does not hide missing evidence. No cloud queries, provisioning or scanner installation. Saves reports
          with findings, evidence and remediation; --json prints the report for automation. This is a scoped local
          assessment, not live verification or provider certification. Missing/stale/manual evidence stays unknown.
          Initial rules retain manual UNKNOWN items; a failure-free report is INCOMPLETE, not an overall PASS.
  all     applicable security scans, one report each, then a summary (FIPS only on FIPS environments).
          Architecture is explicit: run `cs scan architecture` separately.

--host takes bastion, vpn and k8s, comma-separated or repeated (any case); an unknown value stops with exit code 2.
Reports: <workdir>/scans/<kind>-<run>.json + .md; raw tool output under <workdir>/scans/raw/. Every scan is logged in
the audit trail. Exit code: 1 when a verdict is FAIL or `scan all` could not run one of its scans (like chaos run and
dr test), else 0. Architecture exits 0 on PASS, 1 on definite findings (FAIL), or 3 when evidence is missing,
stale or needs manual review (INCOMPLETE); invalid arguments exit 2. FAIL takes precedence over INCOMPLETE.

EXAMPLES
  cs scan all
  cs scan cis; cs scan kube --framework nsa,mitre,cis-v1.10.0
  cs scan host azure --env prod --profile stig
  cs scan stig aws --env prod --host vpn         # the Ubuntu VPN host (the AL2023 bastion has no STIG content)
  cs scan cloud gcp --env prod
  cs scan fips vmware --env lab
  cs scan architecture aws --env prod --profile production --max-age-days 30 --json
  cs scan architecture vmware --env lab --profile lab
""",
    "disable": """\
cloudseed disable agentic | headliner | mcp | ui

Turns the feature off. With agentic off, only deterministic commands run. `disable mcp` also stops the deployed MCP server;
`disable ui` stops the web console and removes its user service.

EXAMPLES
  cloudseed disable headliner
  cloudseed disable agentic
  cloudseed disable ui
""",
    "use": """\
cloudseed use [builtin|claude|codex|gemini|grok] [--model ID]

Selects the agent for `cloudseed agentic`, installs its CLI (when it is an npm/pip/brew install and you
agree) and the cloudseed skills into its skills directory. `builtin` uses the Claude API directly
from the CLI and needs no external tool. Custom agents: ~/.cloudseed/agents.json.

EXAMPLES
  cloudseed use builtin --model claude-opus-5
  cloudseed use claude
""",
    "agents": """\
cloudseed agents

Lists every agent with what it is, whether it is installed, whether it is logged in, and the exact
install / login command when it is not. Also shown by `cloudseed use help` and `cloudseed agentic --agent help`.

  builtin  cloudseed's own loop on the Claude API (official SDK). Needs ANTHROPIC_API_KEY or `ant auth login`;
           otherwise it falls back to your logged-in Claude Code.
  claude   Claude Code CLI - your claude.ai subscription login works, no key needed.
  codex    OpenAI Codex CLI - `codex login` or OPENAI_API_KEY.
  gemini   Gemini CLI - log in with Google once (`gemini`) or set GEMINI_API_KEY.
  grok     community Grok CLI - set GROK_API_KEY (xAI).

EXAMPLES
  cloudseed agents
  cloudseed use gemini
  cloudseed agentic --agent codex "list my environments"
""",
    "model": """\
cloudseed model [ID] [--agent NAME]
cloudseed model --forget ID [--agent NAME]

Without ID: shows the selected agent (builtin when none is selected yet), its selected model (*) and the known models.
With ID: selects that model. Unknown ids are accepted and remembered as custom (in a terminal after a confirmation,
with a did-you-mean hint for likely typos); --forget removes a remembered custom id again.

EXAMPLES
  cloudseed model
  cloudseed model claude-opus-5
  cloudseed model gpt-5-codex --agent codex
""",
    "agentic": """\
cloudseed agentic [--agent NAME] [--model ID] [-i|--interactive] [--no-headliner] [--show-prompt] [--force] "<task>"
(alias: cloudseed do ...   short: cs agentic "...")

Hands a natural-language task to the selected agent, which then drives cloudseed for you using the
bundled skills. Everything after the flags is the task, so quote it; cloudseed's own flags may also follow the task
(cs agentic "list envs" --model X), and `--` makes the rest literal task text. Requires `cloudseed enable agentic`
(or --force for a one-off). Deterministic commands are never affected: `cloudseed setup aws` is always the
literal command; `cloudseed agentic "set up aws"` is the request to the agent.

  -i, --interactive   open the agent's interactive session instead of one-shot mode (external agents)
  --no-headliner      skip the research brief for this run
  --show-prompt       print the (redacted) prompt that is sent
  --force             one-off run even if agentic mode is disabled
  --agent / --model   override the selected agent / model for this run

Agents: builtin (Claude API), claude (Claude Code - used automatically when no API key is set),
codex, gemini, grok. Credentials are never given to the agent: env secrets are stripped, prompts and
outputs are redacted. With the built-in agent, commands that change things pause for your approval (provision, scans,
vpn add-user/provision, --auto-approve, ...: the full list is below), and human-only commands are refused in
every agent session.

EXAMPLES
  cloudseed agentic "create a staging environment on gcp in europe-west1"
  cloudseed agentic "set up a dev env on aws and apply it without asking"
  cs agentic "are the bastions of my environments reachable?"
  cloudseed agentic --model claude-opus-5 "tear down azure-dev completely"
  cloudseed agentic --show-prompt "list my environments"
""",
    "skill": """\
cloudseed skill list
cloudseed skill install [names...] [--agent NAME] [--project] [--dir PATH]
cloudseed skill show <name>

The 10 bundled skills follow the SKILL.md Agent Skills format used by Claude Code, Codex, Gemini CLI and others:
cloudseed (the driver skill) plus cloudseed-aws, -gcp, -azure, -vmware (targets), -destroy (safe teardown),
-platform (Kubernetes day-2: env, node, platform, dr, chaos, scan), -finops, -managed (Databricks / Snowflake) and
-architecture (Well-Architected assessments and how cloudseed works). `cloudseed skill list` shows them with their descriptions; `skill show <name>`
prints one. Names can be short (aws, gcp, azure, vmware, destroy, platform, finops, managed, architecture) or full
(cloudseed-aws); an unknown name is refused before anything is copied.
`install` copies them (all bundled skills when no names are given) into the agent's skills directory (~/.claude/skills,
~/.codex/skills, ...), into ./.<agent>/skills with --project, or anywhere with --dir. The built-in agent (the default)
reads the skills straight from cloudseed, so for it they go to Claude Code's directory (./.claude/skills with --project).
The built-in agent puts the core cloudseed skill plus the skills a task needs into its prompt, with an index of the
others (it reads them with `skill show`). Grok cannot load skills from a directory: cloudseed sends the core skill and
the task's skills in each Grok prompt, and `skill install --agent grok` installs them for Claude Code.

EXAMPLES
  cloudseed skill list
  cloudseed skill install --agent claude
  cloudseed skill install aws destroy --agent codex
  cloudseed skill install --project
  cloudseed skill show aws
""",
    "install": """\
cloudseed install <what...> [--agent NAME] [--dir PATH] [--project] [--engine docker|podman] [--rebuild]

One front door for everything installable. Several targets can be given at once.

  TOOLS      terraform | aws | gcloud | az | kubectl | helm | k9s | databricks | snow | go | qemu-img | openvpn | tailscale
             | gke-gcloud-auth-plugin | kubescape | trivy
             Homebrew when available. Otherwise: terraform, kubectl, helm, go, k9s and databricks from their official
             releases, SHA256-verified, into ~/.cloudseed/bin; aws and gcloud from the vendors' installers (HTTPS);
             az and snow with pip into their own virtualenv (needs Python 3.10+); qemu-img, openvpn and tailscale
             from the OS package manager (tailscale: its install script). gke-gcloud-auth-plugin comes with gcloud
             (or on its own); kubescape and trivy are installed when named, or by cs scan on first use.
  GROUPS     all     terraform aws gcloud az kubectl helm go qemu-img openvpn tailscale vmware-provider skills
             cloud   terraform aws gcloud az          aws-deps | gcp-deps | azure-deps   just one cloud
             vmware  terraform go qemu-img vmware-provider
             vpn     openvpn tailscale
             kubernetes (or k8s)  kubectl helm
             (databricks, snow, k9s and vmrun are installed only when named)
  PROVIDER   vmware-provider   build cloudseed's Terraform provider for Fusion/Workstation (--rebuild to rebuild)
  VMWARE     vmrun [--from FILE]   install VMware Fusion Pro / Workstation Pro from the downloaded installer.
             Broadcom serves the free installer only after a login, so cloudseed opens the download page,
             waits for the file in ~/Downloads, mounts/installs it and launches it once. `setup vmware` does
             this automatically when VMware is missing.
  LIST       cloudseed install list   shows every target with its current status
  SKILLS     skills [<name> ...]   (every bundled skill when no names are given; short names such as aws, vmware,
             destroy or platform, or full names such as cloudseed-aws; the words right after `skills` name skills,
             so `install skills vmware` is the vmware skill, not the VMware tool group; see cs skill list)
             into the selected agent's skills dir (~/.claude/skills, ~/.codex/skills, ~/.gemini/skills),
             --agent to choose, --project for ./.<agent>/skills, --dir for anywhere. Grok cannot load skills from a
             directory: cloudseed sends them in each Grok prompt, and --agent grok installs them for Claude Code.
  AGENTS     builtin | claude | codex | gemini | grok
             installs the agent CLI (npm/pip/brew, with your OK) or the Anthropic SDK, plus the skills; it becomes the
             selected agent only when none is selected yet (`cloudseed use <agent>` switches).
  RUNTIME    image      build the all-in-one container image (Docker/Podman)
             bundle     build dist/cloudseed-<os>-<arch>, a single binary with Terraform embedded

Long forms: `cloudseed skill install ...`, `cloudseed use <agent>`, `cloudseed deps image|bundle`. `cloudseed deps
install <tool...>` installs single tools only (its `all` is terraform aws gcloud az); groups, skills, agents, the
VMware provider and `vmrun --from FILE` are `install` targets.

Installing is yours, not an agent's: in every agent session (CLOUDSEED_AGENT set: the built-in agent, Claude Code,
Codex, Gemini, Grok) cloudseed refuses `install` (all but list/help), `deps install|image|bundle|runtime` and
`skill install` with exit code 2 and the command for you to run; the skills tell the agents to hand it to you, and MCP
clients reach `install` only through its tool, which needs your confirm=true. (Codex and Grok have a full shell, so for
them the rule is advisory: they could unset the variable.)

EXAMPLES
  cloudseed install list                      # what can be installed, what is already there
  cloudseed install terraform
  cloudseed install all                       # cloud CLIs, kubectl + helm, VMware tools + provider, VPN clients, skills
  cloudseed install cloud                     # terraform + aws + gcloud + az
  cloudseed install vmware                    # go + qemu-img + the VMware provider
  cloudseed install skills                    # all cloudseed skills for the selected/Claude agent
  cloudseed install skills aws destroy --agent codex
  cloudseed install claude                    # Claude Code CLI + skills, and select it
  cloudseed install image --engine podman
  cloudseed install terraform skills image    # several at once
""",
    "explain": """\
cloudseed explain [<feature> | <target> | <command> | <topic> | platform [<group>|<item>] | <item>]
cloudseed explain feature|target|topic|command|group|item <name>      (explicit: no guessing)
cloudseed explain variables|outputs <cloud>
cloudseed explain variable <cloud> <name>      (one setup setting; `cs explain <cloud> <name>` works too)
cloudseed explain ... --json                   (the same page as data; exit 1 when nothing matches)

Deterministic explanation of anything cloudseed does - for you and for the agent:
  <feature>   how it is implemented: files, resources, security controls, where state/logs live, commands
              (overview network bastion security-baseline state kubernetes platform vpn vmware provisioning finops
              managed-data agentic reconcile mcp prereqs fips chaos dr scan architecture operations undo ui audit dependencies)
  <target>    aws | gcp | azure | vmware: what is built there, every variable and output (= cs help aws|gcp|azure|vmware-skill)
  <command>   the full help page of that command (same as cs help <command>)
  <topic>     quickstart deps agents envs services destroy troubleshooting examples ... (same as cs help <topic>)
  platform    the catalog; `platform <group>` = every tool the group brings; `platform <item>` or just `<item>` =
              chart source, version, namespace, dependencies, per-target values, notes
  variable    one stack variable or setup input of a target: what it sets, its default, how to set it, the setup
              question that asks for it (cs explain variable aws single_nat_gateway = cs explain aws single_nat_gateway)
A bare word that names several things is looked up in this order: feature > target > platform group / item >
command / topic, and an "also:" line names the others (cs explain vmware shows the vmware feature and the vmware
target, then "also: cs explain topic vmware"). The namespace form picks one: cs explain topic security,
cs explain group security, cs explain target vmware.
No argument lists everything. Typos get a "did you mean" from all of these names.

The same pages everywhere: --json prints one as data (query, found, kind, name, title, summary, sections, text,
commands, also, did_you_mean, cli, error). The web console opens them in its Explain panel from every "?" button,
the ? key (the page you are on) and the "Explain: <name>" entries of its ⌘K search, reading
GET /api/explain?q=<query> and /api/explain/names; MCP clients call cloudseed_explain with format=json or read the
resource cloudseed://explain/<query>. Agents: look a thing up here before guessing how it works.

EXAMPLES
  cs explain
  cs explain kubernetes
  cs explain vmware
  cs explain topic security
  cs explain platform security
  cs explain istio
  cs explain variables gcp
  cs explain aws single_nat_gateway
  cs explain vpn --json
""",
    "help": """\
cloudseed help [command | topic] [cloud]

Examples: cloudseed help setup · cloudseed help security · cloudseed help variables aws

EXAMPLES
  cloudseed help
  cloudseed help setup
  cloudseed help security
  cloudseed help variables aws
""",
}

COMMANDS["ops"] = """\
cloudseed ops list --json
cloudseed ops ACTION [aws|gcp|azure|vmware] --env NAME [--params '{...}'] [--approve] [--json]
cloudseed ops spec-export aws --env prod --output cloudseed.yaml --approve --json
cloudseed ops spec-validate --input cloudseed.yaml --json

A shared operation contract drives CLI, MCP (cloudseed_ops_ACTION with underscores), web-console All actions >
Operations & readiness, and bundled agent skills. List actions and accepted parameters with ops list --json.

ACTIONS
  health / network       local evidence by default; --live queries deployed resources. network --active --live
                         --approve creates and cleans a temporary diagnostic workload. Unknown evidence is not healthy.
  profile                --profile lab|team|production previews real topology and partial cost estimates; --approve
                         saves configuration only. Terraform apply and backup/platform installation remain separate.
  spec-export            portable schema_version=1 document, excluding credentials, keys, state and local paths
  spec-validate/diff      --input cloudseed.yaml validates or compares a portable document; no cloud calls
  spec-import            preview the validated change; --approve saves under the environment lock, never applies
  policy-check           budget/coverage, supplied Terraform JSON plan and destructive-change policy preview
  expiry-plan            preview expiry cleanup eligibility
  expiry-cleanup         cleanup requires saved elapsed expiry, saved opt-in and --approve; no timer; no state purge
  drift                  read provider/state/config drift without applying changes
  upgrade-plan           --target-version VERSION --backup NAME; review compatibility and backup gates
  upgrade-apply          --plan PATH takes the fresh reviewed plan; --approve executes it
  recovery-plan          --namespace NAME inspects the selected application restore prerequisites
  recovery-test          restore into a separate restricted namespace; --namespace NAME and --approve required
  acceptance             preview without credentials, or explicitly authorize an isolated sandbox lifecycle
  credentials-backend    inspect/preview/approve file or native OS-keychain credential storage
  release-verify         check an artifact's trusted digest and optional GitHub provenance; never executes the file

NOTES
Production topology means AWS per-AZ NAT, regional GKE with explicit node zones and AKS Standard tier/zones.
GKE node count/min/max are per zone. Provider availability/quota requires live validation. VMware profiles remain
one physical host. Backup/platform sections express desired intent; use dr/platform commands to make them live.
Offline costs omit traffic, regional/contract pricing and usage; they cannot guarantee a billing cap. Saved budgets
block apply on incomplete coverage by default. Explicit deletion-only cleanup may proceed without trapping resources
behind a creation budget. Normal applies/replacements still obey destructive and budget gates.

JSON/YAML specs accept simple mappings/scalar lists and JSON flow values. No tags, aliases, anchors, duplicate keys,
block strings or multiple documents; 512 KiB maximum. Exported JSON is valid YAML 1.2.
Reports: <workdir>/operations, shown in console Reports. Exit 0=pass/preview, 1=fail/blocked, 3=incomplete, 2=invalid.
Live acceptance needs a sandbox identity, region, cost estimate/time limit and public SSH source; local tests do not
claim live cloud acceptance. Follow scenarios 16-19 in the documentation.
EXAMPLES
  cs ops health aws --env prod --live --json
  cs ops network aws --env prod --live --active --approve --json
  cs ops profile gcp --env prod --profile production --json
  cs ops spec-diff aws --env prod --input cloudseed.yaml --json
  cs ops policy-check aws --env prod --params '{"budget_max_monthly":500}' --json
  cs ops acceptance aws --json

"""


TOPICS: dict[str, str] = {
    "fips": """\
FIPS 140 MODE  (cloudseed setup <cloud> --var fips_mode=true)

One switch for the whole environment; everything cloudseed puts into it must be FIPS-capable or setup / install refuses.

  AWS       provider + S3 state backend use the FIPS endpoints (so only us-east-1/2, us-west-1/2 and the GovCloud
            regions); EKS node groups use Bottlerocket FIPS AMIs; the bastion (Amazon Linux 2023) gets
            `fips-mode-setup --enable` (kernel fips=1, FIPS crypto policy) and a reboot. The VPN host is Ubuntu: it
            attaches Ubuntu Pro (export UBUNTU_PRO_TOKEN before setup) and enables fips-updates.
  GCP       bastion and VPN host use the Ubuntu Pro FIPS 22.04 image (metered, no token needed); GKE nodes stay on
            Container-Optimized OS (FIPS-validated kernel crypto module and BoringCrypto). A custom bastion_image must
            be Ubuntu (a plain Ubuntu image without Pro needs UBUNTU_PRO_TOKEN) or RHEL-family; others are refused.
  Azure     bastion/VPN use the Ubuntu Pro FIPS marketplace image (terms accepted for you); the AKS node pool is created
            with fips_enabled = true.
  VMware    every VM attaches Ubuntu Pro (export UBUNTU_PRO_TOKEN - free for personal use) and enables fips-updates, then
            reboots; guest_os must be Ubuntu; Kubernetes must be RKE2 (FIPS-validated Go crypto; kubeadm is refused).
  hosts     sshd offers only FIPS-approved algorithms (AES-GCM/CTR, SHA-2 HMACs, ECDH P-curves, RSA/ECDSA host keys);
            environments are created with an RSA-4096 SSH key (id_rsa) instead of ed25519: ed25519 is not FIPS-approved
            and EC2 and Azure refuse ECDSA. A key you bring must be RSA-3072 or larger (RSA-4096 on AWS), or ECDSA on GCP / VMware;
            OpenVPN restricts data and TLS ciphers to AES-GCM suites; Tailscale (WireGuard/ChaCha20) is refused.
  platform  catalog items come in four tiers: compatible (controllers and services: installed), tls-restricted
            (the TLS terminators envoy-gateway and ingress-nginx: installed with TLS pinned to 1.2+ and FIPS cipher
            suites, but their proxy crypto is not a validated module, so `cs scan fips` flags them), crypto-restricted
            (items whose job is cryptography in a non-validated module - cert-manager, sealed-secrets, velero,
            cloudnative-pg: installed, since the platform needs them, and flagged the same way) and the rest
            (application stacks whose images ship their own crypto: refused unless --force, and listed by
            `cs scan fips`).
  verify    cs scan fips   (and `cs scan stig` for the DISA STIG, which includes FIPS checks). On AWS, `cs scan cloud`
            audits only the environment's region, through the FIPS endpoints (the report's summary names them).

UBUNTU_PRO_TOKEN (VMware, AWS with a VPN host, a GCP bastion on a plain Ubuntu image): export it, or store it with
`cs creds set UBUNTU_PRO_TOKEN`, before setup applies - a setup that would apply stops without it, nothing created;
--dry-run and --plan-only only warn.
FIPS mode is chosen at creation time (the SSH key type depends on it); it cannot be toggled on an existing environment.
""",
    "quickstart": """\
QUICKSTART

  1. cloudseed doctor                 # what's installed, how you're authenticated
  2. log in:  aws configure | gcloud auth application-default login | az login
  3. cloudseed setup aws              # answer the prompts; a plan is shown before anything is created
  4. cloudseed ssh aws --env dev      # you're on the bastion; workloads go in the private subnets
  5. cloudseed status aws --env dev   # outputs: subnet IDs, workload SG / tag, bastion IP
  6. cloudseed destroy aws --env dev  # when you're done (clean slate: --purge-state --purge)

Non-interactive: add -y and the flags for every answer, plus --auto-approve.
""",
    "security": """\
SECURITY MODEL

Network
  - Only the bastion (and the optional VPN host) has a public address. The cloud firewall admits TCP/22 from --allow-ip
    only: IPv4, nothing wider than a /8 and at most two /8s in all (0.0.0.0/0 is refused), a range written as its
    network (an address with host bits such as 203.0.113.7/24 is refused); `update-ip` changes it. The host's own
    nftables firewall denies all other inbound traffic.
  - Workloads live in private subnets behind NAT; the isolated data tier (AWS) has no internet route.
  - Default security groups are stripped (AWS); explicit deny-all inbound rules on GCP (logged) and on Azure NSGs
    (not logged: NSG / VNet flow logs are not managed yet).
  - Bastion egress is limited (AWS): 443/80 for updates, NTP, SSH into the VPC.

Hosts
  - Key-only SSH, root login and password auth disabled, latest LTS images, encrypted disks.
  - AWS: IMDSv2 required, SSM Session Manager available as a no-inbound alternative.
  - GCP: Shielded VM, dedicated least-privilege service account, project SSH keys blocked.
  - Azure: Trusted Launch (secure boot + vTPM), managed identity.

Logging & account baseline
  - VPC / subnet flow logs, NAT and firewall logging (AWS, GCP); Azure: no NSG / VNet flow logs yet.
  - AWS, in two halves. Account-wide (enable_account_baseline, one environment per account): multi-region CloudTrail
    with validation + KMS, S3 account public-access block, IAM password policy. Regional (enable_regional_baseline,
    one environment per account AND region; it follows enable_account_baseline unless set): EBS default encryption
    (AWS-managed aws/ebs key), GuardDuty, Access Analyzer (one per region: --var enable_access_analyzer=false when one
    exists), optional Security Hub FSBP (which turns on AWS Config recording; --var enable_aws_config=false where
    Config already records). A second environment in the same region: --var enable_account_baseline=false; one alone
    in another region: add --var enable_regional_baseline=true. An existing GuardDuty detector, Security Hub or
    account Access Analyzer is never adopted: while it is only on by default here, setup leaves it alone and saves
    enable_guardduty=false (enable_access_analyzer=false) with the environment; one you set true explicitly stops setup
    before anything changes (pass --var enable_guardduty=false / enable_security_hub=false).
    A full destroy leaves the S3 public-access block, EBS default encryption, the password policy and the AWS Config
    service-linked role in place (no longer managed) and deletes CloudTrail, GuardDuty, Access Analyzer, Security Hub
    and the Config recorder.
  - GCP: _Default log bucket retention, optional Data Access audit logs (allServices). Both are project-wide: one
    environment per project manages them (--var enable_project_baseline=false for the others), and a destroy keeps
    both - the retention stays at the value cloudseed set, the audit logs stay on.
  - Azure: Activity Log -> Log Analytics, optional Microsoft Defender for Servers / Storage (subscription-wide: enable
    it in one environment only; destroy leaves it on).

State
  - Remote state buckets are versioned, encrypted, private, TLS-only; no secrets are stored in state.

Agentic mode
  - Agents never receive credentials: secret env vars (and the vault's secrets) are stripped from the agent's
    environment and served to child cloudseed commands over a per-session unix socket (nothing on disk; the session
    ends with the agent); prompts and cloudseed's output are redacted, kubectl, helm, databricks and snowflake output
    included. They run without a terminal there, so k9s, kubectl edit, kubectl exec/attach/run/debug -i/-t, calls
    that never end (logs -f, get/events -w, port-forward, proxy: use --tail/--since or kubectl wait --timeout), a
    browser sign-in (databricks auth login), prompts and the interactive snow sql shell are refused with exit code 2:
    run those in your own terminal. `dr schedule --ttl 30d` is taken as 720h.
  - The built-in agent can only run cloudseed commands. In every agent session cloudseed itself refuses agentic,
    enable, disable and the changing forms of install, deps, skill, creds, use, model, ui and mcp with the command for
    you; their read-only forms work (creds list, model, use list, install list, ui status|logs, mcp
    status|guide|tools|config|test|logs, deps status, skill list|show). The built-in agent also refuses ssh, k9s and
    mcp serve, and its changes need your approval. Claude Code runs with cloudseed's secret files denied; Codex, Gemini and
    Grok can read any file you can, so only the skills keep them away from credential/state files.
""",
    "state": """\
TERRAFORM STATE

  remote (default)  cloudseed first creates hardened state storage in your account:
                    AWS S3 (versioned, SSE-KMS, TLS-only, native lockfile locking),
                    GCS (versioned, public-access prevention), Azure Storage (TLS1.2, versioning, soft delete).
                    Backend config is saved in the env config; the bucket is only deleted with --purge-state.
  local             <workdir>/stack/terraform.tfstate  (default workdir: ~/.cloudseed/envs/<cloud>-<env>)

Switching: re-run `cloudseed setup <cloud> --env <env> --state local|remote`; state is migrated automatically.
Rendered roots (main.tf.json) live next to the state; the checked-in Terraform stays generic.
""",
    "deps": """\
DEPENDENCIES AND RUNTIMES

Required: terraform (>= 1.10), ssh-keygen.   Optional: aws, gcloud, az (auth convenience only).

  cloudseed deps install terraform         Homebrew (hashicorp/tap/terraform) or verified release -> ~/.cloudseed/bin
  cloudseed deps install aws gcloud az     Homebrew, or the vendors' installers / pip into ~/.cloudseed (no sudo)
  cloudseed deps image                     build cloudseed:local with Docker or Podman (asked once); kubectl and
                                           helm are in the image
  cloudseed --runtime container setup aws  run one command in the container: CLOUDSEED_HOME is mounted at the same
                                           path (so recorded paths stay valid), plus ~/.aws, ~/.config/gcloud,
                                           ~/.azure; AWS_*/GOOGLE_*/ARM_* env is passed. Tools the container installs
                                           live in ~/.cloudseed/container-linux-<arch>/, apart from the host's
  cloudseed deps runtime container         make the container the default runtime
  cloudseed deps bundle                    build dist/cloudseed-<os>-<arch> (Terraform embedded)

Authentication is done by Terraform's providers: env vars, AWS profiles/SSO, Google ADC, `az login`.
""",
    "agentic": """\
AGENTIC MODE

  cloudseed enable agentic                default agent = builtin (Claude API inside the CLI)
  cloudseed use builtin|claude|codex|gemini|grok
  cloudseed model [id]                    list / select models for the chosen agent
  cloudseed agentic "<task>"              (alias: cloudseed do; short: cs agentic "...")
  cloudseed disable headliner             send bare tasks (brief is on by default)

Headliner: before the agent runs, the CLI gathers environments, outputs, tool + credential status and a
command cheat-sheet into a compact brief. The agent starts informed instead of exploring - fewer tokens.

Built-in agent: official Anthropic SDK, installed on first use into ~/.cloudseed/venv-agent. Needs
ANTHROPIC_API_KEY or an `ant auth login` profile. Without those, cloudseed automatically falls back to your
logged-in Claude Code CLI (`claude`) when it is installed - a claude.ai subscription login works only there.
Models: claude-opus-5 (default), claude-opus-5-5, claude-fable-5-1, claude-sonnet-5.
Its only tool runs `cloudseed <args>`. It follows the policy every agent session shares (below): agentic, enable,
disable and the changing forms of install, deps, skill, creds, use, model, ui and mcp are refused, and so are ssh and
k9s (they need your terminal) and mcp serve (the server itself, which runs until stopped). Their read-only forms work:
creds list, model, use list, install list, ui status|logs, mcp status|guide|tools|config|test|logs, deps status,
skill list|show.
Commands that change things wait for your approval: any --auto-approve, --purge*, provision, scans (all but
architecture, fips and reports), vpn add-user/provision/revoke/connect/disconnect, platform install/ui, chaos run/stop,
dr backup/schedule/test, mutating kubectl/helm (also options that point them at another server, identity or local file),
helm template/lint, reading cluster secrets (kubectl get secret / --raw, helm get values|all|manifest|hooks, helm
status -o json|yaml), and databricks/snowflake commands other than status/test. destroy, undo, node add/remove/scale,
platform uninstall, dr restore and chaos run --target run unasked as a preview first (without --auto-approve they stop
at exit 3, nothing changed), so you approve once, with the plan on screen. Refused and unapproved calls are shown to
you too. Without a terminal approvals are refused unless CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE is 1, true, yes or on.
Skills: the core cloudseed skill plus the skills the task needs go into its prompt, with an index of the others (it
reads them with `cloudseed skill show <name>`).

External agents: their CLI is launched with the task; cloudseed skills are installed into the agent's
skills directory (Grok cannot load skills: the core skill and the task's skills go into each Grok prompt).
In every agent session (CLOUDSEED_AGENT set) cloudseed itself refuses what changes your machine or its settings -
install, deps install|image|bundle|runtime, skill install, creds set/unset/clear, use <agent>, model <id>|--forget,
enable, disable, ui (all but status|logs), mcp (all but status|guide|tools|config|test|serve|logs), agentic - with
exit code 2 and the command for you to run; the read-only forms (creds list, model, use list, install list, ui
status|logs, mcp status|guide|tools|config|test|logs, deps status, skill list|show) stay available. Codex and Grok
have a full shell, so for them that rule is advisory.
Command templates per agent are in cloudseed/agents.py, overridable in ~/.cloudseed/agents.json: {prompt} and {model}
are replaced anywhere inside a word; without a model a bare {model} and the option right before it are dropped, and a
word containing {model} is dropped (the codex template passes --skip-git-repo-check).
""",
    "envs": """\
ENVIRONMENTS AND CONFIG

Each environment has a working directory, created by cloudseed: ~/.cloudseed/envs/<cloud>-<env> by default,
or any path given with `setup --workdir PATH` (remembered in ~/.cloudseed/workdirs.json). It contains:
  config.json      everything you answered (name, region, CIDR, allowed IPs, vars, tags, state backend)
  ssh/             generated key pair: ed25519, RSA-4096 in FIPS mode (unless you supplied one); known_hosts
  logs/            audit.jsonl + one redacted log per command;  inventory.json  what exists + history
  stack/           rendered Terraform root (main.tf.json), provider cache, local state
  bootstrap/       root for the remote state storage
  outputs.json     cached outputs (used by `ssh`, `list`, the headliner)

Naming: every resource is <name>-<env>-<thing>; tags/labels Project, Environment, Owner, ManagedBy=cloudseed,
CloudseedEnv=<cloud>-<env> and CloudseedEnvId (the environment's unique id) plus your --tag values. Tag keys are
case-insensitive (--tag owner=alice sets Owner), --tag KEY= removes a saved tag, and ManagedBy, CloudseedEnv and
CloudseedEnvId cannot be set (reconcile reads them to tell this environment's resources from anyone else's).
Defaults are picked for you: name=cloudseed, env=dev, CIDR=first free 10.N.0.0/16, region from env vars or a
sensible default.
""",
    "destroy": COMMANDS["destroy"],
    "vmware": """\
LOCAL VIRTUAL MACHINES (cloudseed setup vmware)

Same shape as a cloud environment, on your own machine:
  - VMware Fusion Pro 13+ (macOS, Intel or Apple Silicon) or Workstation Pro 17+ (Linux; Windows detection is
    experimental, and native environment changes are unsupported: no locking or native Ansible control node) - both free; older releases are refused for new environments.
    cloudseed detects which one is installed (VMWARE_HOME when set: a wrong one is reported by name), its version, and
    the host architecture, and picks matching guest images (arm64 guests on Apple Silicon, amd64 elsewhere).
  - A bastion VM with two NICs: NAT (reachable from your machine) and a private host-only network it
    routes/NATs for. Optional workload VMs live only on the private network (`--var workload_count=N`).
  - The private network is VMware's built-in host-only vmnet (vmnet1 on Fusion): its subnet and DHCP setting are
    adopted (VMware serves DHCP on its upper half, e.g. .128-.254) and the VMs use fixed addresses below the DHCP pool:
    bastion .2, workloads .10+ (at most 10 with Kubernetes on), control planes .20-.39 (1-20), workers .40-.99 (at
    most 60 on a /24): .100-.127, just below VMware's DHCP pool, are kept for MetalLB's LoadBalancer pool. An
    existing cluster that already has more workers is warned, not refused (remove the ones above wk60 before using
    LoadBalancer services).
    Every environment without --cidr gets that same vmnet, so only one of them can have VMs: a second one is refused
    while another has VMs. `--cidr X` asks for a dedicated vmnet with DHCP off instead (VMware only lets root create
    networks: run `sudo vmrest` and export VMREST_USER/VMREST_PASSWORD for it). An explicit --cidr must be a private
    (RFC 1918) range: a public one would hide the real hosts of that range from this computer, and one containing
    1.1.1.1 or 8.8.8.8 would also cut the VMs off from their DNS servers.
    With Kubernetes on, the network must not overlap the cluster's pod or Service range (RKE2 10.42.0.0/16 +
    10.43.0.0/16, kubeadm 10.244.0.0/16 + 10.96.0.0/16): setup refuses it for a new environment or when Kubernetes is
    turned on, and only warns for a cluster that already runs there.
  - Guest OS: ubuntu-24.04 (default), ubuntu-22.04, debian-12 (`--var guest_os=...`). Official cloud images
    are downloaded and checksum-verified; qcow2 images are converted with qemu-img (installed on demand).
  - cloud-init (NoCloud ISO + VMware guestinfo) creates your user with the generated SSH key; Ansible then
    hardens the bastion exactly like in the cloud (nftables also NATs the private network). Workload VMs are not
    Ansible-hardened: cloud-init bootstraps them and turns on unattended security updates (VMs created by this
    version). Kubernetes nodes are hardened by the Kubernetes play and deliberately not auto-updated (node upgrades
    are yours to schedule).
  - Terraform all the way: cloudseed ships its own provider (providers/vmdesktop, Go) built once on first
    use into ~/.cloudseed/providers and wired through ~/.cloudseed/terraform.rc; building it needs Go >= 1.25
    (`cs doctor` shows an older Go as too old; `cs install go` upgrades it). Resources:
    vmdesktop_network (adopts or creates a vmnet via vmrest), vmdesktop_vm (vmrun + vmware-vdiskmanager),
    data vmdesktop_host.
  - Kubernetes on VMs: `--var enable_kubernetes=true` adds control-plane and worker VMs on the private network and
    installs RKE2 (default: single binary, Canal CNI) or kubeadm (upstream, containerd + Flannel) with Ansible run
    from this machine (installed into ~/.cloudseed/venv-ansible on first use). RKE2's CIS hardening profile is not
    enabled unless --var kubernetes_cis_profile=true (RKE2 only; it enforces the restricted Pod Security Standard
    outside the exempt namespaces - RKE2's system ones plus cloudseed-scan, velero, local-path-storage, minio and
    chaos-mesh -, and `cs platform install` labels the namespaces of catalog items that need privileged or baseline
    pods before installing them; `cs platform info <item>` shows the level). Nodes added later join at the version
    the cluster runs, and adding a control plane leaves the workers alone. kubernetes_version pins the release instead (RKE2: v1.36.4+rke2r1, installed by
    every new node; kubeadm: 1.35, for a new cluster only; empty = RKE2's stable channel / kubeadm's supported
    default); it never upgrades a node that is already installed. The kubeconfig lands in
    <workdir>/k8s/kubeconfig; `cs k8s kubeconfig vmware` merges it into ~/.kube/config and makes it the current
    context.
    Sizes: kubernetes_control_planes (1), kubernetes_workers (2; 0 = the control planes run the workloads),
    kubernetes_cpus/memory_mb/disk_gb.
  - Sizes can change later: CPUs and memory in place (the VM restarts), a larger *_disk_gb grows the disk in place,
    a smaller one rebuilds the VM (the plan shows it as a replace). Floors: 1 vCPU, 512 MB of memory in multiples of
    4, 10 GB of disk (Kubernetes nodes 20 GB); kubeadm needs 2 vCPUs and 2048 MB per node, RKE2 2048 MB; no VM may
    have more vCPUs or memory than this computer.
  - Rebuilds: changing `packages` rebuilds the bastion and the workload VMs; ssh_username, the SSH key, guest_os,
    vm_dir or --name rebuild every VM, Kubernetes nodes included (the plan says "must be replaced"). To add packages
    to running VMs, install them over `cloudseed ssh` instead.
  - A VM bundle in vm_dir named like one of this environment's VMs but unknown to its state (an earlier environment of
    the same name, lost state) is moved aside to <name>.replaced-<time>.vmwarevm, never deleted; a running one stops
    the apply.
  - State is always local, inside the environment's working directory (`--workdir PATH` to choose it). The VM files
    go to <workdir>/vms (vm_dir: an absolute path, ~/..., or a path relative to the working directory). No VPN is
    needed (the host talks to the bastion directly); update-ip does not apply.
  - destroy removes only this environment's VMs and files (other VMs in vm_dir are left alone); with --purge it stops
    vmrest only when cloudseed started it and nothing else uses it.

If VMware is missing, `setup vmware` opens Broadcom's download page (free, login required), waits for the
installer in ~/Downloads and installs it (`cloudseed install vmrun [--from FILE]` does the same on demand).

VMware's REST service (vmrest) is configured by cloudseed itself: it generates credentials, runs `vmrest -C`
non-interactively, stores them in ~/.cloudseed/vmware.json (0600) and starts vmrest in the background. Set
VMREST_USER/VMREST_PASSWORD only if you want to use your own (then run `vmrest -C` yourself once when vmrest was never
configured for this OS user; cloudseed says so).

EXAMPLES
  cloudseed setup vmware                                  # bastion only
  cloudseed setup vmware --env lab --var workload_count=2 --var guest_os=debian-12
  cloudseed ssh vmware --env lab
  cloudseed status vmware --env lab                       # workload_private_ips, private_vmnet
  cloudseed destroy vmware --env lab
  cloudseed install vmware-provider --rebuild             # rebuild the provider after changing its source
""",
    "services": """\
OPTIONAL SERVICES (enable per environment with --var, or answer the setup prompts)

  enable_kubernetes=true   private Kubernetes: EKS / GKE / AKS, RKE2 or kubeadm VMs on vmware   -> cloudseed help k8s
  enable_vpn=true          VPN host: OpenVPN (default) or Tailscale (cloud targets) -> cloudseed help vpn
  vpn_type=tailscale       subnet router instead of OpenVPN (needs TS_AUTHKEY)

After `setup` applies, `provision` copies this repo to the bastion and VPN host and configures them with
Ansible (hardening + tools + VPN server). Everything is re-runnable: cloudseed provision <cloud> --env <env>.
""",
    "troubleshooting": """\
TROUBLESHOOTING

  "terraform is not installed"            cloudseed deps install terraform   (or --runtime container)
  No credentials detected                 run the login command doctor prints; or export the provider env vars
  "already exists" errors                 cloudseed adopts the resource when its tags say it is this environment's (asks when
                                          the owner is unknown; CLOUDSEED_ADOPT=1 without a terminal) - cs explain reconcile
  GuardDuty / Security Hub already on     never adopted. Only on by default here: left alone, enable_guardduty=false /
                                          enable_access_analyzer=false saved for you. Set true explicitly: setup stops;
                                          --var enable_guardduty=false / --var enable_security_hub=false; an account
                                          analyzer already in the region: --var enable_access_analyzer=false
  Second env in the same AWS account      --var enable_account_baseline=false (same region); an env alone in another
                                          region also takes --var enable_regional_baseline=true
  SSH times out                           cloudseed update-ip <cloud> --env <env>   (your IP changed)
  Azure activity log permission error     --var enable_activity_log=false (needs Contributor at subscription scope)
  Azure 403 on role assignments (AKS)     AKS / velero create role assignments (velero also a custom role): Owner, or
                                          Contributor + User Access Administrator
  Provider checksum errors                after switching host <-> container: cloudseed resets the cache itself; re-run.
                                          Any other checksum / lock error: delete that root's .terraform.lock.hcl and
                                          .terraform, then re-run (with a shared TF_PLUGIN_CACHE_DIR, let parallel runs
                                          finish first)
  Plan shown, nothing applied (exit 3)    add --auto-approve (a plan with no changes exits 0)
  "<cloud>-<env> is busy"                 another cloudseed run (a terminal, the console, an MCP client or an agent) is
                                          changing that environment; wait for it to finish (or stop it), then re-run
  Agent auth failed                       set ANTHROPIC_API_KEY, `ant auth login`, or `cloudseed use claude` (Claude Code login)
  "unknown command" for a sentence        natural language goes through: cloudseed agentic "<sentence>"
  Something failed and it's unclear why   cloudseed troubleshoot <cloud> --env <env> --log
  "Unexpected error"                      the redacted traceback is in the environment's log, or without an environment in
                                          ~/.cloudseed/logs/<ts>-<cmd>-crash.log (0600); CLOUDSEED_DEBUG=1 prints it too
  A missing tool stops a -y run (exit 2)  install it first (cloudseed install <tool>) or set CLOUDSEED_AUTO_INSTALL=1
  A script or CI job must never prompt    -y on every command, or export CLOUDSEED_NONINTERACTIVE=1 (same as -y)
  Where is everything?                    cloudseed list · ~/.cloudseed (CLOUDSEED_HOME)
""",
    "examples": """\
EXAMPLES

  # Interactive first environment
  cloudseed setup aws

  # Fully scripted prod environment with per-AZ NAT and 3 AZs
  cloudseed setup aws -y --env prod --name acme --region eu-west-1 \\
    --allow-ip 203.0.113.7 --var az_count=3 --var single_nat_gateway=false --auto-approve

  # GCP with OS Login and a bigger bastion
  cloudseed setup gcp --env dev --project-id my-proj --var enable_os_login=true --var bastion_machine_type=e2-small

  # Azure, local state, Defender on
  cloudseed setup azure --env dev --subscription-id <id> --state local --var enable_defender=true

  # Day-2
  cloudseed update-ip aws --env prod
  cloudseed ssh aws --env prod -- -L 8080:10.0.16.5:80
  cloudseed output aws --env prod --json

  # Teardown
  cloudseed destroy aws --env prod --target module.stack.module.bastion   # just the bastion
  cloudseed destroy aws --env prod --purge-state --purge                   # everything, clean slate

  # Agentic
  cloudseed enable agentic
  cloudseed agentic "set up a dev env on gcp in project my-proj, then show me the ssh command"
  cs agentic "list my environments"
""",
}



# Commands that share another command's page: argparse aliases and pass-through tools. They are real COMMANDS keys, so
# `cs help helm`, `cs helm --help` (epilog + description), error hints and `cs explain helm` all find a page.
ALIASES: dict[str, str] = {"do": "agentic", "databricks": "managed", "snowflake": "managed", "helm": "kubectl", "k9s": "kubectl"}
for _alias, _target in ALIASES.items():
    COMMANDS.setdefault(_alias, COMMANDS[_target])

CLOUDS = ("aws", "gcp", "azure", "vmware")
# help topics rendered from skills/cloudseed-<target>/SKILL.md plus the generated variable / output reference
SKILL_TOPICS = {"aws": "aws", "gcp": "gcp", "azure": "azure", "vmware-skill": "vmware"}


def has_page(topic: str | None, cloud: str | None = None) -> bool:
    """True when `cloudseed help <topic> [cloud]` has a real page (the overview for no topic)."""
    if not topic:
        return True
    if topic in ("variables", "outputs"):
        return cloud in CLOUDS
    return topic in COMMANDS or topic in TOPICS or topic in SKILL_TOPICS


def _parse_variables(cloud: str) -> list[tuple[str, str, str]]:
    text = (paths.tf_root() / cloud / "variables.tf").read_text()
    out = []
    for m in re.finditer(r'variable\s+"([^"]+)"\s*\{(.*?)\n\}', text, re.S):
        name, body = m.group(1), m.group(2)
        desc = re.search(r'description\s*=\s*"((?:[^"\\]|\\.)*)"', body)
        default = re.search(r"default\s*=\s*(.+)", body)
        out.append((name, desc.group(1) if desc else "", default.group(1).strip() if default else "(required)"))
    return out


def _hcl_blocks(text: str, kind: str) -> list[tuple[str, str]]:
    """Top-level `<kind> "name" { ... }` blocks of a .tf file with their text. A block runs until the next top-level block
    starts, so braces inside values ("${...}", maps, one-line blocks) never cut a description off."""
    starts = [m for m in re.finditer(r'^([a-z_]+)[ \t]+"([^"]+)"', text, re.M)]
    out = []
    for i, m in enumerate(starts):
        if m.group(1) == kind:
            end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
            out.append((m.group(2), text[m.end():end]))
    return out


def _hcl_description(body: str) -> str:
    m = re.search(r'\bdescription\s*=\s*"((?:[^"\\]|\\.)*)"', body)
    return m.group(1).replace('\\"', '"').replace("\\\\", "\\") if m else ""


def _parse_outputs(cloud: str) -> list[tuple[str, str]]:
    text = (paths.tf_root() / cloud / "outputs.tf").read_text()
    return [(name, _hcl_description(body)) for name, body in _hcl_blocks(text, "output")]


_FIRST_FREE = "--cidr (default: the first free 10.N.0.0/16 across your environments)"
# the tags / labels clouds.base.Cloud.tags puts on every resource (GCP: the same names in lower case)
_IDENTITY_TAGS = "Project/Environment/Owner/ManagedBy/CloudseedEnv/CloudseedEnvId"
# How cloudseed sets the stack variables it refuses in --var (clouds.Cloud.managed_vars; cli._parse_setup_vars): shown
# with the flag to use instead of a Terraform default. The network CIDR and the SSH allow-list are also kept in the
# environment's config (overlap checks, VPN routes, update-ip), so they are set with their flags, never with --var.
_SET_BY_CLOUDSEED: dict[str, dict[str, str]] = {
    "*": {"name": "--name (default: cloudseed)", "environment": "--env (default: dev)",
          "allowed_ssh_cidrs": "--allow-ip or `cloudseed update-ip` (default: your public IP)",
          "ssh_public_key": "the environment's generated key, or --ssh-public-key",
          "platform_prereqs": "managed by `cloudseed platform install <item>` (never set it by hand)"},
    "aws": {"vpc_cidr": _FIRST_FREE, "tags": _IDENTITY_TAGS + " + --tag KEY=VALUE"},
    "gcp": {"network_cidr": _FIRST_FREE, "region": "--region", "labels": _IDENTITY_TAGS.lower() + " + --tag KEY=VALUE",
            "os_login_member": "your gcloud account, registered by setup when enable_os_login=true"},
    "azure": {"network_cidr": _FIRST_FREE, "location": "--region", "tags": _IDENTITY_TAGS + " + --tag KEY=VALUE"},
    "vmware": {"private_cidr": "--cidr for a dedicated vmnet (default: the subnet of VMware's built-in host-only vmnet)",
               "base_disk": "--var guest_os=... (the downloaded, checksum-verified image of guest_os)",
               "guest_os_id": "--var guest_os=... (derived from guest_os and the host architecture)",
               "tags": "--tag is accepted but not applied (VMware VMs have no tags)"},
}
# Stack variables whose default is computed by cloudseed (overridable): shown instead of the Terraform literal.
# "{sources}" becomes the question's flag and the environment variables it reads (Question.env): the list cannot drift.
_COMPUTED_DEFAULTS: dict[str, dict[str, str]] = {
    "gcp": {"zone": "<region>-a, or <region>-b in us-east1 / europe-west1 (--zone)",
            "ssh_username": "your local username (--ssh-username)",
            "project_id": "none: {sources}"},
    "azure": {"admin_username": "azureuser (--admin-username)", "subscription_id": "the one `az account show` names"},
    "vmware": {"vm_dir": "<workdir>/vms", "ssh_username": "your local username (--ssh-username)"},
}


def _or_list(words) -> str:
    """'a', 'a or b', 'a, b or c'."""
    words = [str(w) for w in words]
    return " or ".join(words) if len(words) < 3 else ", ".join(words[:-1]) + " or " + words[-1]


def _shown_default(value) -> str:
    """A setup input's default the way the CLI prints values (cli._fmt): true / false and JSON collections; text as it
    is (ubuntu-24.04 gets no quotes); nothing is '-'."""
    import json
    if value is None or value == "":
        return "-"
    if isinstance(value, (bool, list, dict)):
        return json.dumps(value)
    return str(value)


def _cloud_questions(cloud: str) -> list:
    try:
        from . import clouds
        return list(clouds.CLOUDS[cloud].questions)
    except Exception:  # noqa: BLE001 - the page must render even if an adapter cannot be imported
        return []


def _question_choices(q) -> list[str]:
    """The accepted answers of an enumerated setup question: its own `choices`, else (guest_os) the known images."""
    if getattr(q, "choices", None):
        return list(q.choices)
    if getattr(q, "key", "") == "guest_os":
        try:
            from . import localvm
            return list(localvm.IMAGES)
        except Exception:  # noqa: BLE001
            return []
    return []


def _as_statement(prompt: str) -> str:
    """A setup question's prompt used as a description: without the question mark ('Create a VPN host ...?')."""
    return prompt.rstrip().rstrip("?").rstrip()


def _question_flag(q) -> str | None:
    """The setup flag of a question that has one (clouds.base.Question.FLAG_KEYS), else None (--var KEY=VALUE)."""
    return q.flag if getattr(q, "key", None) in getattr(type(q), "FLAG_KEYS", ()) else None


def _refused_vars(cloud: str, declared: set[str], questions: list) -> dict[str, str]:
    """The declared stack variables setup refuses in --var (cloudseed sets them itself) -> how they are set instead.
    The same rule as cli._managed_vars: what the adapter computes (Cloud.managed_vars) plus the known managed names,
    minus the prompted settings (a --var for a question is its answer)."""
    texts = dict(_SET_BY_CLOUDSEED["*"], **_SET_BY_CLOUDSEED.get(cloud, {}))
    qkeys = {q.key for q in questions}
    try:
        from . import clouds
        from .clouds import base
        derived = clouds.CLOUDS[cloud].managed_vars()
        flags = dict(base.MANAGED_VAR_FLAGS, **{k: v for k, v in derived.items() if k not in base.MANAGED_VAR_FLAGS})
    except Exception:  # noqa: BLE001 - the page must render even if an adapter cannot be imported
        flags = dict(texts)
    return {k: texts.get(k, flags[k]) for k in flags if k in declared and k not in qkeys}


def variables_page(cloud: str) -> str:
    variables = _parse_variables(cloud)
    questions = _cloud_questions(cloud)
    prompts = {q.key: q.prompt for q in questions}
    owned = _refused_vars(cloud, {n for n, _, _ in variables}, questions)
    computed = dict(_COMPUTED_DEFAULTS.get(cloud, {}))
    for q in questions:
        if "{sources}" in computed.get(q.key, ""):
            sources = ([_question_flag(q)] if _question_flag(q) else []) + list(q.env)
            computed[q.key] = computed[q.key].replace("{sources}", _or_list(sources) or "an answer")
    shown = [v for v in variables if v[0] not in owned]
    w = max([len(n) for n, _, _ in shown] + [20]) + 2
    lines = [f"STACK VARIABLES FOR {cloud.upper()}   (override with --var name=value, JSON for lists and maps; "
             "--var name=null drops a saved override)", ""]
    for name, desc, default in shown:
        lines.append(f"  {name:<{w}} default: {computed.get(name, default)}")
        desc = desc or _as_statement(prompts.get(name, ""))
        if desc:
            # never split a name at its hyphens (local-path-storage, ubuntu-24.04, gke-gcloud-auth-plugin)
            lines.append(textwrap.indent(textwrap.fill(desc, 84, break_long_words=False, break_on_hyphens=False), "      "))
    declared = {n for n, _, _ in variables}
    extra = [q for q in questions if q.key not in declared]
    if extra:
        lines += ["", "SETUP INPUTS   (asked by setup; not Terraform variables, but --var KEY=VALUE works too)", ""]
        for q in extra:
            default = computed.get(q.key) or (_shown_default(q.default) if not callable(q.default) else "(computed)")
            sources = ([_question_flag(q)] if _question_flag(q) else []) + list(q.env)
            head = f"  {q.key:<{w}} default: {default}"
            lines.append(head + (f"   ({_or_list(sources)})" if sources else ""))
            choices = _question_choices(q)
            text = _as_statement(q.prompt) + (f" - one of: {', '.join(choices)}" if choices and ", ".join(choices) not in q.prompt else "")
            # never split a name at its hyphens (local-path-storage, ubuntu-24.04, gke-gcloud-auth-plugin)
            lines.append(textwrap.indent(textwrap.fill(text, 84, break_long_words=False, break_on_hyphens=False), "      "))
    present = [(n, owned[n]) for n, _, _ in variables if n in owned]
    if present:
        lines += ["", "SET BY CLOUDSEED   (refused in --var: use the flag shown)", ""]
        lines += [f"  {n:<{w}} {how}" for n, how in present]
    return "\n".join(lines)


def outputs_page(cloud: str) -> str:
    rows = _parse_outputs(cloud)
    w = min(max([len(n) for n, _ in rows] + [20]) + 2, 32)
    lines = [f"STACK OUTPUTS FOR {cloud.upper()}   (cloudseed output {cloud} --env <env> [--json])", ""]
    for name, desc in rows:
        if len(name) + 2 > w and desc:          # very long names: the description goes on its own line
            lines += [f"  {name}", f"  {'':<{w}} {desc}"]
        else:
            lines.append(f"  {name:<{w}} {desc}".rstrip())
    return "\n".join(lines)


def _md_inline(s: str) -> str:
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", s)
    s = re.sub(r"\*\*(.+?)\*\*", r"\1", s)
    return s.replace("`", "")


def md_to_text(md: str, drop: tuple[str, ...] = (), width: int = 100) -> str:
    """Render a SKILL.md body as help text: '# title' -> first line, '## section' -> an upper-case heading, bullets and
    paragraphs re-wrapped with hanging indents, emphasis and backticks removed. Sections whose heading starts with a
    word in `drop` are left out (the generated variable / output pages replace them)."""
    items: list[tuple[str, str]] = []   # (kind, text): title | head | bullet:<marker> | para | blank
    skipping = False
    for raw in md.strip().splitlines():
        line = raw.rstrip()
        h = re.match(r"^(#{1,6})\s+(.*)$", line)
        if h:
            title = _md_inline(h.group(2)).strip()
            if len(h.group(1)) == 1:
                skipping = False
                items.append(("title", title))
                continue
            base = re.sub(r"\s*\(.*\)\s*$", "", title).strip()
            skipping = bool(base) and base.split()[0].lower() in drop
            if not skipping:
                items += [("blank", ""), ("head", re.sub(r"[^A-Z0-9 &/<>,.'-]", "", base.upper()).strip() or base.upper()), ("blank", "")]
            continue
        if skipping:
            continue
        stripped = line.strip()
        if not stripped:
            items.append(("blank", ""))
            continue
        b = re.match(r"^\s*([-*]|\d+\.)\s+(.*)$", line)
        if b:
            items.append(("bullet:" + ("-" if b.group(1) in "-*" else b.group(1)), _md_inline(b.group(2))))
        elif items and items[-1][0].startswith(("bullet", "para")):
            kind, text = items[-1]
            items[-1] = (kind, text + " " + _md_inline(stripped))      # continuation of the previous bullet / paragraph
        else:
            items.append(("para", _md_inline(stripped)))
    out: list[str] = []
    for kind, text in items:
        if kind == "blank":
            if out and out[-1] != "":
                out.append("")
        elif kind in ("title", "head"):
            out.append(text)
        elif kind == "para":
            out.append(textwrap.fill(text, width, initial_indent="  ", subsequent_indent="  ",
                                     break_long_words=False, break_on_hyphens=False))
        else:
            marker = kind.split(":", 1)[1] + " "
            out.append(textwrap.fill(text, width, initial_indent="  " + marker, subsequent_indent=" " * (2 + len(marker)),
                                     break_long_words=False, break_on_hyphens=False))
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)


def _skill_page(topic: str) -> str:
    cloud = SKILL_TOPICS[topic]
    p = paths.REPO_ROOT / "skills" / f"cloudseed-{cloud}" / "SKILL.md"
    parts = []
    if p.exists():
        text = p.read_text()
        body = text.split("---", 2)[2] if text.startswith("---") and text.count("---") >= 2 else text
        parts.append(md_to_text(body, drop=("variables", "outputs")))
    parts += [variables_page(cloud), outputs_page(cloud)]
    return "\n\n".join(x for x in parts if x) + "\n"


def _merge_topic(command_page: str, topic_page: str) -> str:
    """A name that is both a command and a topic (deps, agentic) shows the command page with the topic guide as an
    extra section before EXAMPLES, so neither is shadowed."""
    marker = "\nEXAMPLES\n"
    if marker in command_page:
        head, tail = command_page.split(marker, 1)
        return head.rstrip() + "\n\n" + topic_page.rstrip() + "\n" + marker + tail
    return command_page.rstrip() + "\n\n" + topic_page


def page(topic: str | None, cloud: str | None = None) -> str:
    if not topic:
        return OVERVIEW
    if topic in COMMANDS:
        text = COMMANDS[topic]
        extra = TOPICS.get(ALIASES.get(topic, topic))
        if extra and extra.strip() != text.strip():
            text = _merge_topic(text, extra)
        return text
    if topic in ("variables", "outputs"):
        if cloud not in CLOUDS:
            return f"Usage: cloudseed help {topic} <{'|'.join(CLOUDS)}>"
        return variables_page(cloud) if topic == "variables" else outputs_page(cloud)
    if topic in TOPICS:
        return TOPICS[topic]
    if topic in SKILL_TOPICS:
        return _skill_page(topic)
    near = suggest(topic)
    return (f"No help for '{topic}'." + (f" Did you mean: {', '.join(near)}?" if near else "")
            + "\n\nRun `cloudseed help` for the overview and the list of topics.")


def examples(command: str | None, limit: int = 4) -> list[str]:
    """Example invocations for a command (from its help page). A command that shares another's page (snowflake and
    databricks share 'managed', helm and k9s 'kubectl') gets its own examples first; the page's others only when it
    has none (`do` shows the agentic examples)."""
    text = COMMANDS.get(command or "", "")
    if "EXAMPLES" not in text:
        return []
    lines = [l.strip() for l in text[text.index("EXAMPLES"):].splitlines()[1:] if l.strip() and not l.strip().startswith("#")]
    if command in ALIASES:
        own = [l for l in lines if re.match(r"(?:cs|cloudseed) %s(?:\s|$)" % re.escape(command), l)]
        lines = own or lines
    return lines[:limit]


def help_topics() -> list[str]:
    """Every name `cloudseed help <name>` accepts."""
    return list(dict.fromkeys(list(COMMANDS) + list(TOPICS) + list(SKILL_TOPICS) + ["variables", "outputs"]))


def suggest(word: str, pool=None, n: int = 3, cutoff: float = 0.5) -> list[str]:
    """Close matches for a typo, without duplicates. `pool` defaults to the help topics and targets."""
    import difflib
    candidates = list(dict.fromkeys(str(p) for p in (help_topics() + list(CLOUDS) if pool is None else pool) if p))
    return difflib.get_close_matches(word or "", candidates, n=n, cutoff=cutoff)


def _option_strings(parser) -> list[str]:
    """Every option string of a parser and of its sub-parsers (best effort for nested commands like deps / skill)."""
    import argparse
    out: list[str] = []
    for a in getattr(parser, "_actions", []):
        if isinstance(a, argparse._SubParsersAction):
            for sp in dict.fromkeys(a.choices.values()):
                out += _option_strings(sp)
        else:
            out += list(a.option_strings)
    return list(dict.fromkeys(out))


def parser_suggestions(parser, command: str | None, message: str, bad_word: str | None) -> list[str] | None:
    """'did you mean' candidates for an argparse error, drawn from what that parser accepts: the choices of the argument
    that failed (commands, subcommands, --runtime values, ...) or, for unrecognized options, the options of the command.
    None means "no parser knowledge": error_hint then falls back to the help topics."""
    import argparse
    import difflib
    choices = getattr(parser, "_cs_bad_choices", None)
    if bad_word is not None and choices is not None:
        return difflib.get_close_matches(bad_word, list(dict.fromkeys(str(c) for c in choices)), n=3, cutoff=0.5)
    m = re.search(r"unrecognized arguments: (.*)", message or "")
    if not m:
        return None
    target = parser
    if command:
        for a in getattr(parser, "_actions", []):
            if isinstance(a, argparse._SubParsersAction) and command in a.choices:
                target = a.choices[command]
    options = _option_strings(target)
    near: list[str] = []
    for tok in m.group(1).split():
        if tok.startswith("-") and tok not in ("-", "--"):
            near += difflib.get_close_matches(tok.split("=", 1)[0], options, n=1, cutoff=0.6)
    return list(dict.fromkeys(near))


def _stderr_width() -> int | None:
    """Columns for text written to stderr: $COLUMNS, else stderr's terminal; None when stderr is not a terminal, so logs,
    pipes and captured output keep one line per message."""
    import os
    import sys
    env = os.environ.get("COLUMNS", "")
    if env.isdigit() and int(env) > 0:
        return max(30, int(env))
    try:
        if sys.stderr.isatty():
            return max(30, os.get_terminal_size(sys.stderr.fileno()).columns)
    except (AttributeError, ValueError, OSError):
        pass
    return None


def _exact_topic(word: str | None) -> str | None:
    """`cloudseed help ...` for a word that is exactly a help topic but not a command (quickstart, state, fips, ...)."""
    w = (word or "").strip().lower()
    if not w or (w in COMMANDS and w != "managed") or w not in help_topics():
        return None
    return f"{w} <cloud>" if w in ("variables", "outputs") else w


# parts of an error message that stay on one line when it is wrapped: "quoted" and `backticked` text, and a command
# set off by two spaces or a colon ("...:  cloudseed enable agentic, then ...") up to the next comma / semicolon
_KEEP_WHOLE_RE = re.compile(r'"[^"]*"|`[^`]*`|(?<=  |: )(?:cloudseed|cs) (?:"[^"]*"|[^,;"])*')


def _problem_rows(problem: str, width: int | None) -> list[str]:
    """'✖ problem', wrapped to the width with a hanging indent; a command to copy is never split (_KEEP_WHOLE_RE)."""
    glyph = ui.style("✖", "rose", "bold")
    rows: list[str] = []
    for n, para in enumerate(problem.splitlines() or [""]):
        lead = "  ✖ " if n == 0 else "    "
        if not width:
            rows.append(lead + para)
            continue
        room = width - 4          # a part longer than a whole line is split at its spaces after all
        kept = _KEEP_WHOLE_RE.sub(lambda m: m.group(0).replace(" ", "\x00") if len(m.group(0)) <= room else m.group(0), para)
        wrapped = [r.replace("\x00", " ") for r in _wrap(kept, width, lead, "    ")]
        if not wrapped[0].startswith(lead):     # a word wider than the line moved the text: keep the glyph anyway
            wrapped[0] = lead + wrapped[0].lstrip()
        rows += wrapped
    return [("  " + glyph + r[3:]) if r.startswith("  ✖ ") else r for r in rows]


def error_hint(command: str | None, problem: str = "", bad_word: str | None = None, near: list[str] | None = None,
               width: int | None = None) -> str:
    """Text shown after an error: what went wrong, likely fixes, examples, where to read more. `near` are ready-made
    suggestions (from the parser); without them a bad word is matched against the help topics. It is laid out for
    `width` columns (default: stderr's terminal; 0 = never wrap), like the help pages."""
    import difflib
    w = _stderr_width() if width is None else (width or None)
    out = _problem_rows(problem, w) if problem else []
    topic = _exact_topic(bad_word) if bad_word and not command else None
    if topic:
        # `cs quickstart`: next to an exact topic the parser's fuzzy command matches are far-fetched ("status"); only a
        # close variant stays (envs -> env, outputs -> output, also when the caller brought none), and the corrected
        # command lines cli._unknown_command made (`cloudseed setup aws`, `cloudseed help quickstart`) always stay
        low = bad_word.lower()
        close = difflib.get_close_matches(low, [c for c in COMMANDS if c not in ALIASES], n=2, cutoff=0.85)
        near = [n for n in list(near or []) + close
                if n.startswith("cloudseed ") or difflib.SequenceMatcher(None, low, n).ratio() >= 0.85]
    elif near is None and bad_word:
        # no parser knowledge: only commands and targets are offered as "did you mean" - a help topic that is not a
        # command (quickstart, security ...) is no command to type; it gets its `cloudseed help` line below instead,
        # and a command further from the typo than that topic is left out (securty: security, not setup)
        near = suggest(bad_word, [c for c in COMMANDS if c != "managed"] + list(CLOUDS))
        close = [] if command else suggest(bad_word, [t for t in help_topics() if t not in COMMANDS or t == "managed"], n=1, cutoff=0.6)
        if close:
            low = bad_word.lower()
            best = difflib.SequenceMatcher(None, low, close[0]).ratio()
            near = [n for n in near if difflib.SequenceMatcher(None, low, n).ratio() >= best]
    near = list(dict.fromkeys(near or []))
    lines = [n for n in near if n.startswith("cloudseed ")]     # whole corrected command lines
    words = [n for n in near if not n.startswith("cloudseed ")]  # commands / options a typo is close to
    rows = []
    if near:
        shown = ", ".join(lines or words)
        if lines and words:
            shown += f", or the command{'s' if len(words) > 1 else ''} {', '.join(words)}"
        rows.append(f"    {ui.style('did you mean', 'muted')} {ui.style(shown, 'text', 'bold')}?")
    # the exact topic's own page, named first - but not next to a corrected command line: that line is the answer
    # (cs aws setup -> cloudseed setup aws), or already the page (cs quickstart -> cloudseed help quickstart). A typo
    # of a topic (quickstrt, securty, ...) gets the closest topic when nothing else was suggested
    if topic and not lines:
        rows.insert(0, f"    {ui.style('help topic', 'muted')} {ui.style(f'cloudseed help {topic}', 'text', 'bold')}")
    elif bad_word and not command and not topic and not near:
        close = suggest(bad_word, [t for t in help_topics() if t not in COMMANDS or t == "managed"], n=1, cutoff=0.6)
        if close:
            rows.append(f"    {ui.style('help topic', 'muted')} {ui.style(f'cloudseed help {close[0]}', 'text', 'bold')}")
    out += rows
    ex = examples(command)
    if ex:
        out.append("")
        out.append(f"  {ui.style('━━', 'brand')} {ui.style(f'Examples for cloudseed {command}', 'bold', 'text')}")
        split = [(e.partition("#")[0].rstrip(), e.partition("#")[2].strip()) for e in ex]
        col = max(len(c) for c, _ in split) + 3
        inline = not w or all(4 + (col + 2 + len(m) if m else len(c)) <= w for c, m in split)
        for cmd, comment in split:
            if inline:          # the comments in one column, as on the help page
                out.append("    " + ui.style(cmd, "text") + (" " * (col - len(cmd)) + ui.dim("# " + comment) if comment else ""))
                continue
            for row in _wrap_command(cmd, w, 4):   # too narrow: the command (with shell continuations), its comment below it
                out.append(row[:_indent(row)] + ui.style(row.strip(), "text"))
            out += [ui.dim(r) for r in (_comment_rows(comment, w, " " * 6) if comment else [])]
    elif not command:
        out.append("")
        out.append(f"  {ui.style('━━', 'brand')} {ui.style('Common commands', 'bold', 'text')}")
        for x in ("cloudseed setup aws", "cloudseed status aws --env dev", "cloudseed destroy aws --env dev --select",
                  "cloudseed install terraform", "cloudseed enable agentic"):
            out += [row[:_indent(row)] + ui.style(row.strip(), "text") for row in (_wrap_command(x, w, 4) if w else ["    " + x])]
    out.append("")
    more = [f"more: cloudseed help {command or ''}".rstrip(), "cloudseed help troubleshooting"]
    if w and len("  " + "   ·   ".join(more)) > w:          # narrow: one pointer per line
        out += ["  " + ui.dim(more[0]), "        " + ui.dim(more[1])]
    else:
        out.append("  " + ui.dim("   ·   ".join(more)))
    return "\n".join(out)


def epilog(command: str) -> str:
    """Examples section for argparse --help of a command."""
    text = COMMANDS.get(command, "")
    if "EXAMPLES" in text:
        return "\n" + text[text.index("EXAMPLES"):]
    return ""


# ---------------------------------------------------------------- rendering

def term_width() -> int | None:
    """Columns to lay help text out for: $COLUMNS or the terminal; None when stdout is not a terminal, so pipes and
    scripts get the text unchanged."""
    import os
    import shutil
    import sys
    env = os.environ.get("COLUMNS", "")
    if env.isdigit() and int(env) > 0:
        return max(30, int(env))
    try:
        if sys.stdout.isatty():
            return max(30, shutil.get_terminal_size((100, 24)).columns)
    except (AttributeError, ValueError, OSError):
        pass
    return None


_HEADER_RE = re.compile(r"^[A-Z][A-Z0-9 &/<>,.'-]{3,}(\s*\(.*\))?$")
_CMD_RE = re.compile(r"^\s+(cloudseed|cs) \S")
_OPT_RE = re.compile(r"^\s+--?[a-z]")
_TWO_COL_RE = re.compile(r"^(\s{2,}(\S(?:.*?\S)?)\s{2,})(\S.*)$")
_BULLET_RE = re.compile(r"^(\s*)([-*]|\d+\.)\s+\S")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _split_word(word: str, room: int) -> list[str]:
    """Pieces of a word longer than a whole line, cut after a '/', '|' or ',' (paths, alternatives, lists) so an
    identifier is never cut in the middle of a name; without such a separator the word is left whole."""
    pieces = []
    while len(word) > room:
        cut = max(word.rfind(sep, 0, room) for sep in "/|,")
        if cut <= 0:
            break
        pieces.append(word[:cut + 1])
        word = word[cut + 1:]
    return pieces + [word]


def _wrap(text: str, width: int, first: str, rest: str) -> list[str]:
    longest = max((len(w) for w in text.split()), default=0)
    if len(rest) + longest > width:           # an unbreakable word (URL, path): give it the room instead of overflowing
        rest = " " * max(2, width - longest)
        first = first if len(first) + longest <= width else rest
    room = max(12, width) - max(len(first), len(rest))
    if longest > room:                         # longer than a whole line: split it at a separator, never mid-name
        text = re.sub(r"\S+", lambda m: " ".join(_split_word(m.group(0), room)), text)
        longest = max((len(w) for w in text.split()), default=0)
    return textwrap.wrap(text, max(12, width), initial_indent=first, subsequent_indent=rest,
                         break_long_words=longest > room, break_on_hyphens=False) or [first.rstrip()]


def _wrap_synopsis(text: str, width: int, first: str, rest: str) -> list[str]:
    """Wrap a synopsis line without breaking inside [optional] or <placeholder> groups. A group too long for a line
    is split at the spaces of its outer level only (e.g. between alternatives), never inside a word."""
    room = max(12, width) - max(len(first), len(rest))
    joined = text
    for keep in range(1, 8):                   # protect spaces at bracket depth >= keep, from the outermost level in
        depth, chars = 0, []
        for ch in text:
            depth += ch in "[<"
            depth -= ch in "]>" and depth > 0
            chars.append("\x00" if ch == " " and depth >= keep else ch)
        joined = "".join(chars)
        if max((len(w) for w in joined.split()), default=0) <= room:
            break
    else:
        joined = text
    return [line.replace("\x00", " ") for line in _wrap(joined, width, first, rest)]


def _wrap_command(cmd: str, width: int, ind: int) -> list[str]:
    """Split a long example command at spaces (never inside quotes) with shell line continuations, so every piece
    still copy-pastes as one command."""
    words = re.findall(r"""(?:"[^"]*"|'[^']*'|\S)+""", cmd.strip())
    groups: list[list[str]] = []
    for w in words:                  # an option stays on the line of its value: `--var az_count=3`, `--region eu-west-1`
        last = groups[-1] if groups else None
        if last and len(last) == 1 and last[0].startswith("-") and "=" not in last[0] and last[0] not in ("-", "--") \
                and not w.startswith("-"):
            last.append(w)
        else:
            groups.append([w])
    tokens: list[str] = []
    for g in groups:                 # ... unless the pair is too long for a continuation line: then they part after all
        pair = " ".join(g)
        tokens += g if len(g) > 1 and ind + 4 + len(pair) + 2 > width else [pair]
    lines, cur = [], " " * ind
    for n, tok in enumerate(tokens):
        tail = 2 if n + 1 < len(tokens) else 0     # room for the " \" that a later token may need
        if cur.strip() and len(cur) + 1 + len(tok) + tail > width:
            lines.append(cur + " \\")
            cur = " " * (ind + 4 if ind + 4 + len(tok) <= width else max(ind, width - len(tok))) + tok
        else:
            cur = cur + (" " if cur.strip() else "") + tok
    lines.append(cur)
    return lines


def _header_rows(line: str, width: int | None) -> list[tuple[str, str]]:
    m = re.match(r"^(.*?)\s*(\(.*\))$", line.strip())
    if not width or len(line) + 5 <= width or not m:
        return [("header", line)]
    return [("header", m.group(1))] + [("text", p) for p in _wrap(m.group(2), width, "     ", "      ")]


def _stacked_rows(src: list[str], width: int | None) -> set[int]:
    """Line numbers of the rows of two-column tables whose term column is wider than half the screen and that have a row
    too long for the line: every row of such a table puts its description below the term, not only the long ones, so
    the table reads the same way from top to bottom. A table is a run of rows with the same indent and description
    column; lines aligned with the description column continue the row above; a blank line or anything else ends it."""
    stacked: set[int] = set()
    if not width:
        return stacked
    rows: list[int] = []
    key: tuple[int, int] | None = None
    too_long = False
    for i, raw in enumerate(src + [""]):          # the sentinel ends the last table
        line = raw.rstrip()
        two = _TWO_COL_RE.match(line)
        if key is not None and line.strip() and not two and _indent(line) == key[1]:
            too_long = too_long or len(line) > width      # continuation of the row above
            continue
        k = (_indent(line), len(two.group(1))) if two and line.startswith(" ") else None
        if k is None or k != key:
            if rows and too_long and key is not None and key[1] > width * 0.5:
                stacked.update(rows)
            rows, too_long, key = [], False, k
        if k is not None:
            rows.append(i)
            too_long = too_long or len(line) > width
    return stacked


_SYN_CMD_RE = re.compile(r"^\s*(?:cloudseed|cs) ")


def _synopsis_group(src: list[str], i: int) -> list[str]:
    """The source lines of one synopsis row: src[i] and the lines that continue it - a description indented to the
    row's description column, more arguments of a command, or the rest of a '(' note. A new command line, a new '('
    note or anything at column 0 starts a row of its own."""
    first = src[i].rstrip()
    two = _TWO_COL_RE.match("  " + first)
    note = first.lstrip().startswith("(")
    group = [first]
    for raw in src[i + 1:]:
        nxt = raw.rstrip()
        if not nxt.strip() or not nxt.startswith(" ") or _SYN_CMD_RE.match(nxt):
            break
        opens_note = nxt.lstrip().startswith("(")
        if two:
            if _indent("  " + nxt) != len(two.group(1)):
                break
        elif note:
            if opens_note or _indent(nxt) != _indent(first):
                break
        elif opens_note:
            break
        group.append(nxt)
    return group


def _syn_desc_kind(desc: str) -> str:
    """How the right-hand part of a synopsis row renders: a '(note)' dim ('synnote'), more arguments like the command
    ('synopsis'), a description as plain text ('syntext')."""
    d = desc.lstrip()
    return "synnote" if d.startswith("(") else ("synopsis" if d[:1] in "[<-|" else "syntext")


def _synopsis_rows(group: list[str], width: int | None) -> list[tuple[str, str]]:
    """Lay out one synopsis row (its source lines): kept as written when every line fits (and for pipes), otherwise
    joined and wrapped once - so a description continued on the next source line never ends up one word per line."""
    first = group[0]
    two0 = _TWO_COL_RE.match("  " + first)
    note = first.lstrip().startswith("(")
    if not width or all(len("  " + g) <= width for g in group):
        cont = _syn_desc_kind(two0.group(3)) if two0 else ("synnote" if note else "synopsis")
        return [("synopsis", "  " + first)] + [(cont, "  " + g) for g in group[1:]]
    line = " ".join([first] + [g.strip() for g in group[1:]])
    shown = "  " + line
    m = re.match(r"^((?:cloudseed|cs) [a-z][\w-]* )", line)
    cont = "  " + " " * (len(m.group(1)) if m else (_indent(line) or 4))
    two = None if note else _TWO_COL_RE.match(shown)      # a (note) is one paragraph, whatever its spacing
    out: list[tuple[str, str]] = []
    kind = _syn_desc_kind(two.group(3)) if two else ""
    wrap = _wrap_synopsis if kind == "synopsis" else _wrap     # more arguments: never split inside [ ] or < >
    if two and len(two.group(1)) <= width * 0.5:
        pieces = wrap(two.group(3), width - len(two.group(1)), "", "")
        out.append(("synopsis", two.group(1) + pieces[0]))
        out += [(kind, " " * len(two.group(1)) + p) for p in pieces[1:]]
    elif two:                                      # wide synopsis: its description / note goes below it
        out += [("synopsis", p) for p in _wrap_synopsis(two.group(2), width, "  " + " " * _indent(line), cont)]
        below = " " * (_indent(shown) + 4)
        out += [(kind, p) for p in wrap(two.group(3), width, below, below)]
    else:
        pieces = _wrap_synopsis(line.strip(), width, "  " + " " * _indent(line), cont)
        out.append(("synopsis", pieces[0]))
        out += [("synnote" if note else "synopsis", p) for p in pieces[1:]]
    return out


def _comment_rows(comment: str, width: int, indent: str) -> list[str]:
    """A shell comment wrapped to the width with '# ' on every line, so pasting a wrapped example never runs its words
    as a command."""
    room = max(12, width - len(indent) - 2)
    return [indent + "# " + p.strip() for p in _wrap(" ".join(comment.split()), room, "", "")]


def _layout(text: str, width: int | None, synopsis: bool) -> list[tuple[str, str]]:
    """Lay out a help page for `width` columns. Returns (kind, line) with kind = synopsis | synnote | syntext | header |
    cmd | comment | opt | text | blank; only the first physical line of a wrapped row carries the row's kind
    (continuations are 'text', or in the synopsis block the kind of what they continue)."""
    src = text.splitlines()
    stacked = _stacked_rows(src, width)
    out: list[tuple[str, str]] = []
    i = 0
    in_syn = synopsis
    started = False
    while i < len(src):
        line = src[i].rstrip()
        if not line.strip():
            out.append(("blank", ""))
            if started:
                in_syn = False
            i += 1
            continue
        started = True
        if in_syn:
            group = _synopsis_group(src, i)
            i += len(group)
            out += _synopsis_rows(group, width)
            continue
        if _HEADER_RE.match(line) and not line.startswith(" "):
            out += _header_rows(line, width)
            i += 1
            continue
        ind = _indent(line)
        shift = "  " if ind == 0 else ""           # prose at column 0 lines up with the indented rows
        two = _TWO_COL_RE.match(line)
        if line.lstrip().startswith("# ") and not two:     # a comment line of its own (a caption above an example)
            i += 1
            if not width or len(shift + line) <= width:
                out.append(("comment", shift + line))
            else:
                out += [("comment", p) for p in _comment_rows(line.lstrip()[2:], width, shift + " " * ind)]
            continue
        # an example command (not a sentence that happens to start with "cloudseed ..."): never re-flowed as prose
        is_cmd = bool(_CMD_RE.match(line)) and not line.rstrip().endswith((":", "."))
        if is_cmd and ("#" in line or not two):
            # a command continued with '\' is one command: its later lines are never taken for options or prose
            grp = [line]
            while grp[-1].endswith("\\") and i + len(grp) < len(src) and src[i + len(grp)].strip():
                grp.append(src[i + len(grp)].rstrip())
            i += len(grp)
            if not width or all(len(g) <= width for g in grp):
                out += [("cmd", g) for g in grp]
                continue
            joined = " ".join(g.rstrip().rstrip("\\").strip() for g in grp)
            cmd, sep, comment = joined.partition("#")
            out += [("cmd", p) for p in _wrap_command(cmd, width, ind)]
            if sep:
                out += [("comment", p) for p in _comment_rows(comment, width, " " * (ind + 4))]
            continue
        kind = "cmd" if is_cmd else ("opt" if _OPT_RE.match(line) else "text")
        bullet = _BULLET_RE.match(line)
        cols = {ind}
        if two:
            col = len(two.group(1))
            lead = re.match(r"^(->|[-*•]|\d+\.)\s+", two.group(3))
            cols = {col, col + len(lead.group(0))} if lead else {col}
        elif bullet:
            col = len(bullet.group(0)) - 1
            cols = {col}
        else:
            col = ind
        # a description that is itself a table row ("all     every tool ...") heads a nested table: its aligned
        # two-column lines are rows of their own, not a paragraph to re-flow
        nested = bool(two) and bool(re.search(r"\S {2,}\S", two.group(3)))
        # gather continuation lines: aligned with this row's text, plain (not a new command / option / header / bullet)
        group = [line]
        j = i + 1
        while j < len(src):
            nxt = src[j].rstrip()
            if (not nxt.strip() or _indent(nxt) not in cols or (_HEADER_RE.match(nxt) and not nxt.startswith(" "))
                    or ((_CMD_RE.match(nxt) or _OPT_RE.match(nxt)) and not bullet) or _BULLET_RE.match(nxt)
                    or (_TWO_COL_RE.match(nxt) and (_indent(nxt) == ind or nested))
                    or (not two and not bullet and group[-1].rstrip().endswith((".", ":", "!", "?")))):
                break                                # plain prose: a finished sentence ends the paragraph row
            group.append(nxt)
            j += 1
        row = i
        i = j
        if not width or (row not in stacked and all(len(shift + g) <= width for g in group)):
            out.append((kind, shift + group[0]))
            out += [("text", shift + g) for g in group[1:]]
            continue
        rest = " ".join(g.strip() for g in group[1:])
        if two:
            prefix, desc = two.group(1), (two.group(3) + " " + rest).strip()
            longest = max((len(w) for w in desc.split()), default=0)
            if col > width * 0.5 or col + longest > width or row in stacked:   # term column too wide: description below
                terms = _wrap(two.group(2), width, " " * ind, " " * (ind + 2))
                out.append((kind, terms[0]))
                out += [("text", p) for p in terms[1:]]
                out += [("text", p) for p in _wrap(desc, width, " " * (ind + 4), " " * (ind + 4))]
            else:
                pieces = _wrap(desc, width - col, "", "")
                out.append((kind, prefix + pieces[0]))
                out += [("text", " " * col + p) for p in pieces[1:]]
        else:
            body = (line.strip() + " " + rest).strip()
            ind_ = min(ind, int(width * 0.45))       # a stray deep continuation must not become one word per line
            first_ind = shift + " " * ind_
            pieces = _wrap(body, width, first_ind, shift + " " * min(col, ind_ + (col - ind)))
            out.append((kind, pieces[0]))
            out += [("text", p) for p in pieces[1:]]
    return out


def render(text: str, synopsis: bool = True, width: int | None = None) -> str:
    """Style (and, for a terminal, wrap) a help page: synopsis block, ━━ section headers, commands, options, comments."""
    out = []
    for kind, line in _layout(text, width, synopsis):
        body = line.strip()
        lead = line[: len(line) - len(line.lstrip())]
        if kind == "synopsis":
            two = _TWO_COL_RE.match(line)
            if body.startswith("("):
                out.append(lead + ui.dim(body))
            elif two and _syn_desc_kind(two.group(3)) != "synopsis":   # the command, then what it does / a (note)
                term = two.group(1).rstrip()
                desc = two.group(3)
                out.append(lead + ui.style(term.strip(), "brand", "bold") + two.group(1)[len(term):]
                           + (ui.dim(desc) if desc.startswith("(") else desc))
            else:
                out.append(lead + ui.style(body, "brand", "bold"))
        elif kind == "synnote":
            out.append(lead + ui.dim(body))
        elif kind == "syntext":
            out.append(line)
        elif kind == "header":
            out.append(f"  {ui.style('━━', 'brand')} {ui.style(line.strip(), 'bold', 'text')}")
        elif kind == "cmd":
            two = _TWO_COL_RE.match(line)
            if "#" in line:                          # example: keep the comment column exactly where the page put it
                cmd, sep, comment = line.partition("#")
                body = cmd.rstrip()
                out.append(ui.style(body, "text") + cmd[len(body):] + ui.dim(sep + comment))
            elif two:                                # command table row: the command, then its description
                term = two.group(1).rstrip()
                out.append(ui.style(term, "text") + two.group(1)[len(term):] + two.group(3))
            else:
                out.append(ui.style(line, "text"))
        elif kind == "comment":
            out.append(ui.dim(line))
        elif kind == "opt":
            m = re.match(r"(\s+)(\S+)(.*)", line)
            out.append(m.group(1) + ui.style(m.group(2), "sky") + m.group(3) if m else line)
        else:
            out.append(line)
    return "\n".join(out)


def print_page(topic: str | None, cloud: str | None) -> None:
    print(render(page(topic, cloud), synopsis=True, width=term_width()))
