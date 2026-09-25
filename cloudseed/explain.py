"""`cs explain <feature>`: deterministic, always-current description of how a capability is implemented -
files, resources, controls, where its state/logs live, and the commands around it. The cloudseed-architecture
skill points agents here so questions about the implementation get exact answers."""

from __future__ import annotations

import re

from . import paths, secrets, ui

FEATURES: dict[str, dict] = {
    "operations": {
        "what": "Shared operational workflows: health/network evidence, real deployment profiles, portable specs, cost/destructive guards, explicit expiry cleanup, drift, pinned upgrades, application recovery, sandbox acceptance and release verification.",
        "files": ["cloudseed/operations.py shared contract and transports", "cloudseed/health.py diagnostics", "cloudseed/blueprints.py profiles/specs", "cloudseed/guardrails.py budget/plan/expiry", "cloudseed/lifecycle.py drift/upgrades", "cloudseed/recovery.py application restore", "cloudseed/acceptance.py isolated cloud tests", "cloudseed/credential_store.py native keychain"],
        "controls": ["health/network default to local evidence; live checks are explicit and active probes require approval", "profile/import save intent only; plan/apply and platform/backup changes are separate", "incomplete price coverage cannot pass a configured complete-cost budget", "upgrade plans bind configuration/state/cluster identity and repeat readiness gates", "expiry cleanup requires saved opt-in and elapsed expiry; no scheduler or state purge", "real cloud acceptance remains unverified without sandbox credentials"],
        "state": ["<workdir>/config.json operations policy and desired configuration", "<workdir>/operations JSON/Markdown reports and reviewed upgrade plans", "isolated acceptance home with retained cleanup manifest/state"],
        "commands": ["cs ops list --json", "cs ops health aws --env prod --json", "cs ops profile aws --env prod --profile production --json", "cs ops spec-export aws --env prod --output cloudseed.yaml --json", "cs ops acceptance aws --json"],
    },
    "overview": {
        "what": "cloudseed = stdlib Python CLI (cloudseed/) + generic Terraform stacks (terraform/<target>) rendered per environment as "
                "main.tf.json + Ansible for everything inside hosts (ansible/) + a Helm/kustomize catalog (cloudseed/platform.py) + skills for agents (skills/).",
        "files": ["bin/cloudseed launcher", "cloudseed/cli.py commands and wizard", "cloudseed/clouds/*.py per-target adapters",
                  "terraform/{aws,gcp,azure,vmware} stacks, terraform/*-bootstrap remote state", "ansible/ playbooks + roles",
                  "cloudseed/platform.py catalog, cloudseed/finops.py, cloudseed/provision.py, cloudseed/localvm.py, providers/vmdesktop (Go)"],
        "state": ["<workdir>/config.json answers", "<workdir>/stack/main.tf.json rendered root (+ terraform.tfstate when local)",
                  "<workdir>/inventory.json what exists + history", "<workdir>/logs/ audit.jsonl + per-run logs", "~/.cloudseed/settings.json preferences"],
        "commands": ["cs help", "cs explain <feature>", "cs inventory <cloud> --env X", "cs troubleshoot <cloud> --env X"],
    },
    "network": {
        "what": "One address space per environment (auto-picked non-overlapping 10.N.0.0/16), public subnets for bastion/NAT/VPN, private subnets for "
                "workloads with NAT egress, an isolated data tier on AWS; flow logs on (AWS, GCP); default security groups stripped (AWS); explicit deny-all "
                "on GCP (logged) and on Azure NSGs (not logged: NSG / VNet flow logs are not managed yet).",
        "files": ["terraform/aws/modules/network", "terraform/gcp/modules/network", "terraform/azure/modules/network", "terraform/vmware (adopts VMware's built-in host-only vmnet, or a dedicated one with --cidr)"],
        "controls": ["no public IPs except bastion/VPN", "NAT (AWS NAT GW / Cloud NAT / Azure NAT GW / bastion nftables on vmware)", "VPC/subnet flow logs (AWS, GCP)",
                     "GCP firewall deny-all logged, Azure NSG deny-all", "AWS default SG has no rules"],
        "commands": ["cs setup <cloud> --cidr 10.5.0.0/16", "cs output <cloud> --env X", "cs help variables <cloud>"],
    },
    "bastion": {
        "what": "Single hardened jump host in the public subnet: SSH only from your IP(s) (update-ip when it changes), key-only auth, "
                "IMDSv2/Shielded VM/Trusted Launch, encrypted disk, SSM/OS-login options, then Ansible hardening after apply.",
        "files": ["terraform/<cloud>/modules/bastion", "ansible/bastion.yml + roles/{common,hardening,tools}", "cloudseed/provision.py"],
        "controls": ["allowed_ssh_cidrs: IPv4 only, never 0.0.0.0/0 or anything wider than a /8 (validated)",
                     "SSH sources enforced by the cloud firewall (SG / VPC firewall / NSG), which update-ip changes; host nftables default-deny",
                     "sshd hardening drop-in (no root, no passwords, MaxAuthTries 3, strong KEX/ciphers, AllowUsers)",
                     "fail2ban, unattended security updates, sysctl hardening, auditd rules, sudo logging", "login banner"],
        "commands": ["cs ssh <cloud> --env X", "cs update-ip <cloud> --env X", "cs provision <cloud> --env X --host bastion"],
    },
    "security-baseline": {
        "what": "Account/project/subscription-wide guard rails, each managed by one environment. AWS in two halves: account-wide "
                "(enable_account_baseline: multi-region CloudTrail - validated, KMS -, S3 account public-access block, IAM password policy) and "
                "regional (enable_regional_baseline, following the account answer unless set: EBS default encryption with the AWS-managed aws/ebs "
                "key, GuardDuty, IAM Access Analyzer - one per region -, optional Security Hub FSBP with AWS Config recording). GCP: the _Default "
                "log bucket retention and optional Data Access audit logs (allServices), both project-wide (enable_project_baseline=false in a "
                "second environment of the same project). Azure: Activity Log to Log Analytics, optional Defender. An existing GuardDuty detector, "
                "Security Hub or account Access Analyzer is never adopted: one this environment only has on by default is left alone (its "
                "enable_*=false is saved), one set true explicitly stops setup. A full AWS destroy leaves the S3 public-access block, EBS default encryption, the password "
                "policy and the Config service-linked role in place (unmanaged); GCP keeps the _Default retention it set (never restored) and the "
                "allServices audit config; Azure keeps Defender and the FIPS image terms.",
        "files": ["terraform/aws/modules/security-baseline + modules/kms", "terraform/gcp/modules/security-baseline", "terraform/azure/modules/security-baseline",
                  "cloudseed/clouds/aws.py, azure.py + gcp.py keep_on_destroy"],
        "controls": ["KMS CMK with rotation for flow/CloudWatch logs, CloudTrail and the bastion/VPN disks", "TLS-only bucket policies", "log retention variables",
                     "project/account-wide settings are forgotten on destroy, not deleted: deleting them would switch the protection off for "
                     "everything else in the account or project"],
        "commands": ["cs setup aws --var enable_account_baseline=false (2nd env in the same account and region)",
                     "cs setup aws --var enable_account_baseline=false --var enable_regional_baseline=true (an env alone in another region)",
                     "cs setup aws --var enable_access_analyzer=false (an account analyzer already exists in the region)",
                     "cs setup gcp --var enable_project_baseline=false (2nd env in the same project)", "cs help aws", "cs help gcp"],
    },
    "state": {
        "what": "Terraform state per environment: remote (S3 versioned+KMS+lockfile / GCS versioned / Azure Storage versioned) bootstrapped first, or local; vmware always local.",
        "files": ["terraform/*-bootstrap", "<workdir>/bootstrap/main.tf.json", "<workdir>/stack/main.tf.json", "cloudseed/cli.py _bootstrap_state"],
        "commands": ["cs setup <cloud> --state remote|local", "cs destroy <cloud> --env X --purge-state"],
    },
    "kubernetes": {
        "what": "Managed clusters (EKS/GKE/AKS: private endpoint by default, control-plane logs, workload identity, autoscaling pools; Secrets with KMS "
                "envelope encryption on EKS, platform-managed encryption at rest on GKE/AKS) or self-managed on VMware (RKE2 default / kubeadm via "
                "ansible/kubernetes.yml; kubernetes_version pins the release, never upgrading an installed node; kubernetes_cis_profile=true turns "
                "on RKE2's CIS hardening profile, off by default). Managed pools are resized through the cloud API (cs node add|remove|scale). One kubeconfig per environment; "
                "private endpoints reached through an SSH tunnel via the bastion; `cs k8s kubeconfig` merges the cluster into your kubeconfig and "
                "makes it the current context (cs undo takes it out again).",
        "files": ["terraform/<cloud>/modules/kubernetes", "terraform/vmware/modules/kubernetes (node VMs)", "ansible/kubernetes.yml + roles/{k8s_common,rke2,kubeadm}",
                  "cloudseed/services.py (kubeconfig, tunnel)", "cloudseed/cli.py cmd_node / cmd_ktool"],
        "state": ["<workdir>/k8s/kubeconfig", "<workdir>/k8s/inventory.ini + vars.json + token (vmware)"],
        "commands": ["cs setup <cloud> --var enable_kubernetes=true", "cs k8s info|kubeconfig|tunnel|untunnel <cloud> --env X", "cs node add|list|remove|scale",
                     "cs kubectl ...", "cs helm ...", "cs k9s"],
    },
    "platform": {
        "what": "Curated catalog (cloudseed/platform.py CATALOG) installed with helm upgrade --install / kubectl apply -k, dependency-ordered, values per target+distro, "
                "skip-if-installed, secrets generated per env, private load balancers, UIs exposed as HTTPRoutes on the shared private Envoy Gateway (wildcard TLS "
                "from the cluster CA; Ingress fallback when only ingress-nginx exists).",
        "files": ["cloudseed/platform.py (CATALOG, GROUPS, UIS, POST_MANIFESTS)", "templates/gitlab-ci/.gitlab-ci.yml"],
        "state": ["<workdir>/platform/secrets.json (0600)", "<workdir>/platform/*.yaml applied manifests", "helm releases (cs helm list -A)", "inventory.json history entries platform-install-*"],
        "commands": ["cs platform list|install|uninstall|status", "cs platform ui", "cs platform template gitlab-ci"],
    },
    "vpn": {
        "what": "VPN host in the public subnet: OpenVPN server with an Easy-RSA PKI (EC keys, tls-crypt, CRL) and per-user .ovpn profiles, or Tailscale subnet router. "
                "NATs clients into the private network; ingress/gateway private IPs are reachable through it. "
                "Cloud targets only: on vmware the host-only network is reachable from the laptop directly, so enable_vpn is refused there.",
        "files": ["terraform/<cloud>/modules/vpn", "ansible/vpn.yml + roles/{openvpn,tailscale}", "cloudseed/services.py vpn functions"],
        "state": ["<workdir>/vpn/<user>.ovpn (0600)", "<workdir>/vpn/openvpn.pid/log"],
        "commands": ["cs setup <cloud> --var enable_vpn=true", "cs vpn add-user|users|revoke|connect|disconnect|status <cloud> --env X [name]"],
    },
    "vmware": {
        "what": "Local target on Fusion Pro 13+ / Workstation Pro 17+ (older releases are refused for new environments; Windows: experimental detection only; native environment changes are unsupported) "
                "through cloudseed's own Terraform provider (providers/vmdesktop, "
                "Go): the private network adopts VMware's built-in host-only vmnet (its subnet and DHCP setting; VMs use fixed IPs below the DHCP pool: "
                "bastion .2, workloads .10+, control planes .20-.39, workers .40-.99; .100-.127 are kept for MetalLB's LoadBalancer pool) unless --cidr "
                "asks for a dedicated vmnet via vmrest (a private RFC 1918 range; with Kubernetes on, no network may overlap the cluster's "
                "pod/Service ranges); every env "
                "without --cidr shares that vmnet, so only one of them can have VMs. VMs via vmrun + vmware-vdiskmanager, cloud-init (NoCloud ISO + "
                "guestinfo). Host/arch detection picks arm64/amd64 images; qcow2 converted with qemu-img. The bastion (and the Kubernetes nodes) "
                "are Ansible-hardened; workload VMs are bootstrapped by cloud-init with unattended security updates.",
        "files": ["providers/vmdesktop", "terraform/vmware", "cloudseed/localvm.py (host detect, images, vmrest, provider build, Fusion install)", "cloudseed/clouds/vmware.py"],
        "state": ["~/.cloudseed/providers + terraform.rc (filesystem mirror)", "~/.cloudseed/images cache", "<workdir>/vms VM files", "~/.cloudseed/vmware.json vmrest creds (0600)"],
        "commands": ["cs setup vmware", "cs install vmrun|vmware-provider|qemu-img|go", "cs doctor vmware"],
    },
    "provisioning": {
        "what": "After apply: repository copied to hosts over SSH (never ~/.cloudseed), Ansible runs on the host (bastion/VPN) or from your machine (VMware Kubernetes nodes).",
        "files": ["cloudseed/provision.py", "ansible/bootstrap.sh", "ansible/*.yml"],
        "state": ["config.json provisioned{}", "inventory history provision-*"],
        "commands": ["cs provision <cloud> --env X [--host bastion|vpn|k8s] [--sync-only]"],
    },
    "finops": {
        "what": "Estimate from inventory (list prices in cloudseed/finops.py), actual bills via AWS Cost Explorer / Azure Cost Management, Kubernetes allocation via OpenCost; reports saved for the agent.",
        "files": ["cloudseed/finops.py", "platform catalog group finops (opencost; extras kube-green, kubecost-cost-analyzer)"],
        "state": ["<workdir>/finops/latest.json"],
        "commands": ["cs finops estimate|cloud|k8s|report", "cs platform install finops"],
    },
    "managed-data": {
        "what": "Databricks and Snowflake through their official CLIs with per-environment profiles stored 0600 (--profile, else the current env's, else "
                "'default'): Databricks gets the profile as env vars per call, `snow` as a generated 0600 --config-file (not with -c/--connection/--config-file).",
        "files": ["cloudseed/managed.py"], "state": ["~/.cloudseed/managed.json"],
        "commands": ["cs databricks [--profile P] connect host=https://<workspace> | test | status | <databricks CLI args>",
                     "cs snowflake [--profile P] connect account=<org-acct> user=<u> | test | status | <snow CLI args>",
                     "cs databricks -- <args with the CLI's own --profile>"],
    },
    "agentic": {
        "what": "Optional agent layer: built-in agent (Claude API tool loop with one tool = run cloudseed) or external CLIs (Claude Code, Codex, Gemini, Grok). "
                "Headliner brief (deterministic research) prepended; skills in skills/ installed into the agent; credentials stripped from agent env and redacted from output.",
        "files": ["cloudseed/agents.py", "cloudseed/builtin_agent.py", "cloudseed/headliner.py", "cloudseed/secrets.py", "cloudseed/skills.py", "skills/*/SKILL.md"],
        "controls": ["secret env vars (and the vault's secrets) stripped from the agent and served to child cloudseed commands over a per-session unix socket (nothing on disk)",
                     "redaction of prompts and cloudseed output, kubectl/helm/databricks/snowflake output included (k9s, kubectl edit and "
                     "exec/attach/run/debug -i/-t, calls that never end - logs -f, get -w, port-forward, proxy -, databricks auth login, prompts "
                     "and the interactive snow sql shell are refused in agent sessions, exit 2)",
                     "Claude Code: allowedTools limited to cloudseed; cloudseed's secret files denied (credentials.json, gcp-credentials.json, "
                     "managed.json + managed/, vmware.json, helm/, mcp/, ui/token, sessions/, the undo journal + backups, every environment's ssh/, "
                     "k8s/, vpn/ and platform/, *.ovpn, *.tfstate, ~/.aws, ~/.config/gcloud, ~/.azure, ~/.ssh, ~/.kube, "
                     "~/.docker/config.json); Codex/Gemini/Grok can read any file the user can",
                     "every agent session (CLOUDSEED_AGENT): the CLI refuses what changes the machine or cloudseed's settings - agentic, enable, disable and the changing "
                     "forms of install, deps, skill, creds, use, model, ui and mcp - with exit 2 and the command for the user; their read-only "
                     "forms (creds list, model, use list, install list, ui status|logs, mcp status|guide|tools|config|test|logs, deps status, "
                     "skill list|show) stay available; advisory for full-shell agents; the built-in agent also refuses ssh, k9s and mcp serve",
                     "built-in agent: changes need approval (provision, scans, vpn add-user/provision, --auto-approve, ...; destroy / undo / node "
                     "changes preview first), CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE=1|true|yes|on without a terminal"],
        "commands": ["cs enable agentic", "cs use <agent>", "cs model", 'cs agentic "..."', "cs skill list|install", "cs agents"],
    },
    "reconcile": {
        "what": "Terraform runs survive 'already exists' - but only for what is provably this environment's. Before the plan you review, per-cluster "
                "singletons (the EKS OIDC provider) and the account's AWS Config service-linked role are looked up and imported, so the plan you approve "
                "is the plan that is applied (apply uses exactly that planfile). An existing account-wide singleton (GuardDuty detector, Security Hub) "
                "is never adopted: one the environment only has on by default is left alone (the --var that skips it is saved and the stack "
                "planned again), one set true explicitly stops the run before anything changes and names the --var to pass. After a failed apply every conflicting address is "
                "mapped to an import id (plan values + cloud CLI) and imported only when the object carries this environment's tags (CloudseedEnv + "
                "Owner, or CloudseedEnvId); objects of another environment are refused, objects whose owner cannot be read need a yes (or "
                "CLOUDSEED_ADOPT=1). Then the new plan is shown and approved again (up to 3 rounds). Cloud prerequisites for platform controllers "
                "(EKS OIDC + IRSA roles for LB controller, autoscaler, external-secrets, EBS CSI add-on; GKE/AKS workload identity for external-secrets) "
                "are part of the Kubernetes stack and wired into the charts automatically.",
        "files": ["cloudseed/reconcile.py", "cloudseed/tf.py plan_for_apply / apply_reconciled", "terraform/<cloud>/modules/kubernetes (IRSA / workload identity)"],
        "controls": ["imports only objects tagged as this environment's; another environment's are refused, unknown owners need consent",
                     "after an adoption the new plan needs approval again, and is refused (even with --auto-approve) when it would delete or replace "
                     "anything the approved plan did not",
                     "adopted objects then belong to the environment: cs destroy, and cs undo of the first setup or of that apply, delete them - "
                     "GuardDuty / Security Hub are never adopted: pass --var enable_guardduty=false / enable_security_hub=false",
                     "each adoption is logged in the run log (<workdir>/logs/<ts>-<cmd>.log); adopted resources appear in inventory.json like any state resource"],
        "commands": ["cs setup / cs apply / cs node add (automatic)", "cs troubleshoot ... --log"],
    },
    "mcp": {
        "what": "cloudseed as an MCP server (JSON-RPC, protocol 2025-06-18 with 2025-03-26/2024-11-05 negotiation): one tool per feature generated from "
                "cloudseed/mcp.py TOOLS, resources (cloudseed://environments, cloudseed://skills/<name>), the resource template cloudseed://explain/{query} "
                "(explain.lookup as JSON; cloudseed_explain with format=json returns the same, in-process) and prompts. Two transports: stdio (client launches "
                "`cloudseed mcp serve`) and Streamable HTTP on 127.0.0.1 (+ legacy SSE at /sse) deployed by `cs setup mcp` as a launchd/systemd user service with "
                "a bearer token; the same command writes the client configs (Claude Code, Claude Desktop, Codex, Cursor, Windsurf, Gemini CLI, VS Code) and prints "
                "the connection guide. Each call runs `cloudseed ...` as a child under the credential session broker with redacted output; destructive tools need confirm=true.",
        "files": ["cloudseed/mcp.py (tools, resources, prompts, stdio + http transports, service, client wiring, guide)", "cloudseed/cli.py cmd_mcp_setup / cmd_mcp / cmd_enable / cmd_disable"],
        "state": ["~/.cloudseed/mcp/server.json (transport, host, port, auth, service)", "~/.cloudseed/mcp/token (0600)", "~/.cloudseed/mcp/server.log", "~/.cloudseed/mcp/CONNECT.md",
                  "~/Library/LaunchAgents/io.cloudseed.mcp.plist or ~/.config/systemd/user/cloudseed-mcp.service; a CLOUDSEED_HOME other than "
                  "~/.cloudseed gets its own io.cloudseed.mcp.<home id>.plist / cloudseed-mcp-<home id>.service"],
        "controls": ["loopback only + Origin check + bearer token (unless deployed with --no-auth)", "disabled until enabled; disable stops it",
                     "secrets stripped + redacted",
                     "arguments checked against each tool's input schema before anything runs",
                     "confirm=true for destructive tools: setup apply, apply, destroy, update-ip, provision, node, platform install/uninstall/ui, vpn "
                     "add-user/revoke/provision, ssh commands, install, mutating kubectl/helm, databricks/snowflake beyond status/test/list/get/describe, "
                     "scans other than architecture/fips/reports, dr, chaos, undo; reading Kubernetes Secrets or helm get values|all|manifest|hooks too",
                     "meta commands (agentic, enable/disable, use, model, mcp, ui, creds) are not tools; global actions are undone by the user only "
                     "(cs undo --global or the web console), never through cloudseed_undo",
                     "long calls: 1-hour tool timeout written for Codex / Gemini CLI; Claude Code: MCP_TOOL_TIMEOUT=3600000"],
        "commands": ["cs setup mcp", "cs mcp status", "cs mcp connect <client|all>", "cs mcp guide", "cs mcp tools", "cs mcp test [--http]", "cs mcp serve [--http]", "cs destroy mcp"],
    },
    "prereqs": {
        "what": "Platform items that need cloud resources get them from the environment's own Terraform stack, not from ad-hoc CLI calls: catalog items "
                "declare cloud_prereqs (velero, karpenter); `cs platform install` records them in config.json (platform_prereqs), re-plans and applies the "
                "stack (approval as usual), then installs with the new outputs wired into the chart values. Zero-cost identities (IRSA roles / GSAs / "
                "user-assigned identities for lb-controller, autoscaler, external-secrets, external-dns, ebs-csi) are always created with the cluster.",
        "files": ["terraform/<cloud>/modules/kubernetes/platform.tf", "cloudseed/platform.py missing_prereqs / plan", "cloudseed/cli.py _apply_prereqs"],
        "state": ["config.json platform_prereqs", "outputs: kubernetes_velero_*, kubernetes_karpenter_*, kubernetes_external_dns_*"],
        "controls": ["least-privilege policies per controller", "buckets: versioned, encrypted, private, TLS-only", "identities bound to one namespace/service account"],
        "commands": ["cs platform install velero", "cs platform install karpenter", "cs platform plan velero", "cs output <cloud>"],
    },
    "fips": {
        "what": "fips_mode=true makes the whole environment FIPS 140: FIPS endpoints (AWS provider + S3 backend), FIPS node images (Bottlerocket FIPS on EKS, "
                "AKS fips_enabled, COS on GKE), FIPS hosts with a verified reboot (AWS bastion: AL2023 fips-mode-setup; GCP/Azure bastion + VPN: Ubuntu Pro FIPS "
                "22.04 images; AWS VPN and VMware VMs: Ubuntu Pro fips-updates attached with UBUNTU_PRO_TOKEN), FIPS-only sshd/OpenVPN algorithms, RSA-4096 "
                "SSH keys (ed25519 is not FIPS-approved; EC2 and Azure refuse ECDSA), RKE2 only, Gateway TLS policy, catalog items in tiers (compatible; "
                "tls-restricted: envoy-gateway and ingress-nginx, installed with FIPS TLS suites and flagged by cs scan fips; crypto-restricted: "
                "cert-manager, sealed-secrets, velero and cloudnative-pg, installed and flagged the same way; the rest refused unless --force); setup "
                "refuses non-compliant combinations (kubeadm, tailscale, ed25519 or short RSA keys, non-FIPS AWS regions). cs scan cloud on AWS audits "
                "only the environment's region through the FIPS endpoints.",
        "files": ["terraform/<cloud>/variables.tf fips_mode", "terraform/*/modules/kubernetes (ami_type / fips_enabled / image_type)", "terraform/azure main.tf marketplace agreement",
                  "ansible/roles/fips", "ansible/roles/hardening/templates/sshd-hardening.conf.j2", "cloudseed/cli.py _check_fips / _verify_fips (provision.await_fips)", "cloudseed/netutil.py ensure_ssh_key", "cloudseed/scan.py fips"],
        "controls": ["refuses ed25519 / RSA < 3072 keys (and ECDSA on AWS/Azure), kubeadm, tailscale", "reboot + fips_enabled=1 verified",
                     "platform items gated by FIPS capability"],
        "commands": ["cs setup <cloud> --var fips_mode=true", "cs scan fips", "cs help fips"],
    },
    "chaos": {
        "what": "Chaos Mesh installed on demand; `cs chaos run` deploys a canary (or targets a Deployment), runs experiments (pod/container kill, pod failure, "
                "network delay/loss/partition, DNS error, CPU/memory stress, time skew) with an availability hypothesis sampled from a probe pod and a timed "
                "recovery bound, then prints PASS/FAIL per experiment (a fault that was never injected is an ERROR) and an overall PASS / FAIL / "
                "INCONCLUSIVE verdict (exit 0 only on PASS), and saves JSON + Markdown reports. --duration 15s..1h, --replicas 2..20.",
        "files": ["cloudseed/chaos.py", "cloudseed/platform.py CATALOG chaos-mesh / litmus"],
        "state": ["<workdir>/chaos/report-<run>.json/.md", "namespace cloudseed-chaos (removed unless --keep)"],
        "commands": ["cs chaos run [basic|network|stress|full]", "cs chaos list", "cs chaos status", "cs chaos stop", "cs chaos report"],
    },
    "dr": {
        "what": "Velero with cloud storage + identity created by the stack on demand (MinIO locally), node-agent file-system volume backups, velero CLI "
                "pinned to the server version and fetched only on the user's own run - a terminal, or -y with --auto-approve / "
                "CLOUDSEED_AUTO_INSTALL=1, never an agent session (`cs dr status` and `cs dr backups` read Velero's objects with kubectl and need "
                "no CLI; local clusters: MinIO and local-path 'local' volumes the node agent can back up); `cs dr test` drills "
                "create → backup → delete → restore → verify (a random file written on the volume before the backup must come back, with Completed "
                "PodVolumeBackups/Restores) and reports the measured RTO; exit 1 on FAIL.",
        "files": ["cloudseed/dr.py", "cloudseed/platform.py CATALOG velero", "terraform/<cloud>/modules/kubernetes/platform.tf"],
        "state": ["<workdir>/dr/drill-<run>.json/.md", "bucket kubernetes_velero_bucket / storage account", "namespace velero",
                  "~/.cloudseed/bin/velero (CLI matching the server version)"],
        "commands": ["cs dr status|backup|restore|backups|schedule|test [name] [<cloud> --env NAME]", "cs dr backup [name]", "cs dr restore <backup>",
                     "cs dr schedule <name> --cron \"0 2 * * *\" (UTC)", "cs dr test",
                     "cs dr describe|logs backup|restore <name> [--details] (velero's own view; in the velero pod without a CLI here)"],
    },
    "scan": {
        "what": "One command per scanner with saved reports: kube-bench (CIS, distro-aware benchmarks, EKS STIG), kubescape (NSA/MITRE/CIS), trivy "
                "(operator reports or one-off), OpenSCAP + SCAP Security Guide over SSH (CIS / DISA STIG per host OS), prowler (cloud CIS), and a "
                "cloudseed FIPS verifier (N/A on non-FIPS environments); `cs scan all` runs what applies (FIPS only on FIPS environments). "
                "STIG content exists for Ubuntu 24.04, Ubuntu 22.04 (Ubuntu Pro) and RHEL 8/9: the AL2023 and Debian 12 bastions report n/a. "
                "Exit 1 when a verdict is FAIL or `scan all` could not run a scan. `cs scan architecture` separately assesses saved "
                "configuration and local evidence against Well-Architected guidance; it never queries or changes cloud resources.",
        "files": ["cloudseed/scan.py", "cloudseed/architecture.py", "ansible/scan.yml + roles/openscap"],
        "state": ["<workdir>/scans/<kind>-<run>.json/.md", "<workdir>/scans/raw/ (raw tool output)", "<workdir>/scans/openscap-<run>/<host>/report.html",
                  "~/.cloudseed/venv-prowler",
                  "kubescape / trivy: found on PATH, else installed with Homebrew, else into ~/.cloudseed/bin",
                  "scanners (kubescape, trivy, prowler) are installed only on the user's own run: agent and MCP sessions stop "
                  "with the install command instead"],
        "commands": ["cs scan all", "cs scan cis", "cs scan kube", "cs scan images", "cs scan host --profile stig", "cs scan stig", "cs scan cloud", "cs scan fips", "cs scan architecture --profile production --json", "cs scan reports"],
    },
    "architecture": {
        "what": "A local Well-Architected assessment for an existing environment, using saved configuration and evidence. "
                "AWS and GCP map to six pillars; Azure maps to five pillars with sustainability as separate guidance. "
                "VMware uses local infrastructure best practices, not an official cloud framework. Production is the default "
                "assessment profile; lab relaxes production availability expectations without converting unknown evidence to a pass. "
                "No cloud API queries, provisioning or scanner installation. Configuration describes intent, not verified deployed state.",
        "files": ["cloudseed/architecture.py", "cloudseed/scan.py", "skills/cloudseed-architecture/SKILL.md"],
        "state": ["<workdir>/config.json and saved local evidence are inputs",
                  "<workdir>/scans/architecture-<run>.json/.md are the assessment reports"],
        "controls": ["Evidence freshness defaults to 30 days (--max-age-days)",
                     "Missing, stale and manual-review evidence remains unknown, never a silent pass",
                     "PASS exits 0; definite findings give FAIL / 1; otherwise unresolved evidence gives INCOMPLETE / 3; invalid arguments exit 2",
                     "Provider guidance mapping is scoped; this is not provider certification or a complete organisational review",
                     "Available through the CLI, cloudseed_scan MCP tool, console scan form and bundled architecture skill"],
        "commands": ["cs scan architecture aws --env prod --profile production --max-age-days 30 --json",
                     "cs scan architecture vmware --env lab --profile lab", "cs scan reports", "cs skill show architecture"],
    },
    "undo": {
        "what": "A journal (~/.cloudseed/undo.json, 0600) of the last fifteen state-changing actions per environment and fifteen global ones, "
                "at most five of one kind (reports and info entries have five slots of their own, so they never push a change out), each with its "
                "inverse: setup/update-ip/node/prereqs store the previous config.json (undo = re-apply with it; config.json is rewritten only once that "
                "worked; local cluster nodes the plan deletes are drained first, account/subscription-wide settings it would delete are only dropped "
                "from the state, Velero's bucket is never removed; the first setup of an environment is undone by "
                "destroying it); destroy --target is undone by re-applying, apply by destroying the resources it created; a full destroy (even --purge) records a 'recreate' entry "
                "(config + SSH keys kept; on --purge in ~/.cloudseed/undo/<ts>-<env>/, deleted with the entry) so `cs undo` re-runs setup with the same "
                "settings on new hosts; "
                "provision stores the previous provisioning flags; platform install/uninstall store the item list; vpn add-user / dr backup|schedule store names; "
                "dr test --keep stores the drill namespace and backup; "
                "dr restore, mutating kubectl and helm uninstall take a Velero backup first (their undo deletes the objects and namespaces the change "
                "created, then restores it); helm install/upgrade are inverted with uninstall / rollback; chaos "
                "runs, dr drills, scans and finops reports delete what they produced; installs remove what they placed under ~/.cloudseed/bin; mcp / enable / "
                "disable / ui / creds / use / model store the opposite command or the previous settings (a settings undo writes back only the "
                "keys that command changed); a `k8s kubeconfig` undo takes out only the contexts it merged and switches back to the previous "
                "current context; a file changed since cloudseed wrote it is copied aside (<file>.cloudseed-undo-<time>, folders under "
                "~/.cloudseed/undo-kept/) before an undo replaces or deletes it. `cs undo` takes the newest entry, asks for approval "
                "and performs the inverse; `cs undo --global` takes the newest global one, `--id ID` a listed entry once it is the newest of its "
                "scope, and `--drop` discards an entry that can never succeed. Agents and the MCP server never undo global entries.",
        "files": ["cloudseed/undo.py", "cloudseed/cli.py cmd_undo + undo.record(...) hooks", "cloudseed/mcp.py cloudseed_undo", "cloudseed/web/app.js (↶ Undo)"],
        "state": ["~/.cloudseed/undo.json (0600)", "~/.cloudseed/undo/ (0700: file backups, the config + SSH keys of a purged environment)",
                  "<file>.cloudseed-undo-<time> / ~/.cloudseed/undo-kept/ (your later edits, kept aside by an undo)"],
        "controls": ["approval per undo, like the action it reverts (--auto-approve to skip)",
                     "fifteen real undo points per environment (and fifteen global), at most five of one kind; reports, scans, drills, chaos runs "
                     "and 'info' entries are minor, with five slots of their own, so they never push a real one out",
                     "global entries (settings, agents, MCP, UI, credentials) are undone by the user only: cs undo --global or the web console",
                     "actions performed by an undo are not journaled again (no redo chains)", "read-only commands leave no entry",
                     "'info' entries only print how to revert by hand", "undoing a full destroy re-creates the environment with new hosts; undoing a restore needs Velero",
                     "a dr restore still running (--no-wait) or a kept drill whose backup is still being written is undone only once Velero has finished",
                     "undoing a purge puts the environment back into its own working directory (a custom --workdir is registered again) and makes it "
                     "current again when it was"],
        "commands": ["cs undo", "cs undo --list", "cs undo <cloud> --env NAME --auto-approve", "cs undo --global", "cs undo --id ID [--drop]",
                     "cs help undo"],
    },
    "ui": {
        "what": "Local web console (stdlib http.server, 127.0.0.1, token in the link + X-CS-Token header, Host/Origin checks, CSP, no CDN): forms generated from the same action registry the MCP "
                "server exposes (cloudseed/mcp.py TOOLS + UI-only actions for agents/MCP/deps/VPN client), a setup wizard from each cloud's questions, the platform "
                "catalog with per-group/per-item install, DR/chaos/scan launchers, reports viewer, agents & MCP control, credentials vault, help. Every click runs "
                "`cloudseed ...` as a child process with live SSE output (redacted), so the CLI, the UI and the MCP server share one code path. "
                "A \"?\" beside every view, wizard cloud/field/question, environment card, platform group and item, resilience card, action and dialog "
                "opens the Explain panel: the page `cs explain <thing>` prints, from GET /api/explain (explain.lookup - the same data as "
                "`cs explain --json`, cloudseed_explain format=json and cloudseed://explain/{query}), with its one-line summary as the tooltip; "
                "the ? key explains the current view and the ⌘K palette lists \"Explain: <name>\" for everything explainable (/api/explain/names).",
        "files": ["cloudseed/webui.py", "cloudseed/web/{index.html,app.js,style.css,locked.html}", "cloudseed/creds.py", "cloudseed/cli.py cmd_ui / cmd_creds",
                  "cloudseed/explain.py lookup / names (the Explain panel, its tooltips and the palette's Explain entries)"],
        "state": ["~/.cloudseed/ui/{server.json,token,server.log}", "~/.cloudseed/credentials.json (0600)", "~/Library/LaunchAgents/io.cloudseed.ui.plist or ~/.config/systemd/user/cloudseed-ui.service"],
        "controls": ["loopback only", "token required (in the link for the page, kept in the tab, never a cookie; X-CS-Token header for the API, ?token= only for GET/SSE)",
                     "Host and Origin checks, frame-ancestors 'none'", "only env logs/reports readable, never state or keys", "destructive actions need an explicit tick",
                     "GET /api/explain is documentation: the same token and Host/Origin checks, q of at most 200 characters, answered in-process "
                     "(no job, no audit entry), the caller's words redacted"],
        "commands": ["cs enable ui", "cs ui", "cs ui status|stop|restart|logs|token", "cs disable ui", "cs creds",
                     "cs explain <thing> [--json] (what a \"?\" shows)"],
    },
    "audit": {
        "what": "Every invocation writes audit.jsonl (who/what/when/exit/duration) and a full redacted log; inventory.json tracks resources and every change; "
                "troubleshoot reads them deterministically. An unexpected error keeps its redacted traceback in the env log, or in "
                "~/.cloudseed/logs/<ts>-<cmd>-crash.log (0600) when there is no environment; CLOUDSEED_DEBUG=1 prints it.",
        "files": ["cloudseed/audit.py", "cloudseed/troubleshoot.py"],
        "state": ["<workdir>/logs/audit.jsonl", "<workdir>/logs/<ts>-<cmd>.log", "<workdir>/inventory.json", "~/.cloudseed/logs/audit.jsonl (global)",
                  "~/.cloudseed/logs/<ts>-<cmd>-crash.log", "~/.cloudseed/logs/purged/<cloud>-<env>/ after destroy --purge (audit trail + final inventory)"],
        "commands": ["cs troubleshoot <cloud> --env X --log", "cs inventory <cloud> --env X"],
    },
    "dependencies": {
        "what": "Three ways: install locally (Homebrew, else official releases into ~/.cloudseed/bin - SHA256-verified for terraform, kubectl, helm, go, k9s "
                "and databricks; aws/gcloud from the vendors' installers over HTTPS; az/snow with pip), container image (Docker/Podman; kubectl + helm "
                "included, CLOUDSEED_HOME mounted at the same path, container tools in ~/.cloudseed/container-linux-<arch>), single binary bundle. "
                "Missing tools are installed only after asking (with -y: `cs install <tool>` first, or CLOUDSEED_AUTO_INSTALL=1).",
        "files": ["cloudseed/deps.py", "cloudseed/container.py", "Dockerfile", "scripts/build-bundle.sh"],
        "commands": ["cs install list|<tool>|all|cloud|vmware|vpn|kubernetes", "cs deps runtime container", "cs doctor"],
    },
}


def _width() -> int:
    from . import help as helpmod
    return helpmod.term_width() or 100


def _wrap(text: str, width: int, first: str = "", rest: str = "") -> list[str]:
    from . import help as helpmod
    return helpmod._wrap(" ".join(text.split()), width, first, rest)


def _fit(text: str, n: int) -> str:
    """Cut at a word boundary with an ellipsis."""
    text = " ".join(text.split())
    if len(text) <= n:
        return text
    cut = text[: max(1, n - 1)].rsplit(" ", 1)[0].rstrip(" ,;:(-")
    return cut + "…"


# ---------------------------------------------------------------- one structured source
# `cs explain`, `cs explain --json`, the web console (GET /api/explain and its "?" buttons) and the MCP server
# (cloudseed_explain format=json, cloudseed://explain/{query}) all go through _resolve() and the data builders below:
# the terminal page is rendered from the same resolution and the same data lookup() returns, so they cannot drift.

TITLES: dict[str, str] = {
    "overview": "cloudseed: how the pieces fit together",
    "network": "Network: VPC / VNet, subnets, NAT and flow logs",
    "bastion": "Bastion: the hardened SSH jump host",
    "security-baseline": "Security baseline: account-wide guard rails",
    "state": "Terraform state: remote or local, per environment",
    "kubernetes": "Kubernetes: EKS / GKE / AKS, or RKE2 / kubeadm on VMware",
    "platform": "Platform catalog: Helm / kustomize add-ons in groups",
    "vpn": "VPN: OpenVPN or Tailscale access host",
    "vmware": "VMware: local VMs on Fusion Pro / Workstation Pro",
    "provisioning": "Provisioning: Ansible on the hosts after apply",
    "finops": "FinOps: estimates, cloud bills and OpenCost",
    "managed-data": "Managed data: Databricks and Snowflake",
    "agentic": "Agentic mode: agents that drive cloudseed",
    "reconcile": "Reconcile: surviving 'already exists' safely",
    "mcp": "MCP server: every feature as an agent tool",
    "prereqs": "Cloud prerequisites of platform items",
    "fips": "FIPS 140 mode",
    "chaos": "Chaos engineering: experiments with a verdict",
    "dr": "Disaster recovery: Velero backups, restores and drills",
    "scan": "Scans: security, compliance and Well-Architected assessments",
    "architecture": "Well-Architected: configuration and saved-evidence assessment",
    "undo": "Undo: a journal of inverse actions",
    "ui": "Web console: the local UI",
    "audit": "Audit trail: logs, inventory and crash logs",
    "dependencies": "Dependencies: local tools, container image or bundle",
}

# one plain sentence per page for tooltips and the index (lookup()["summary"]); pages without one use their first sentence
SUMMARIES: dict[str, str] = {
    "feature operations": "Shared health, deployment, policy, upgrade and recovery workflows with explicit evidence and approval gates.",
    "command ops": "Inspect operational readiness, preview configuration and run explicitly approved lifecycle changes.",
    "feature overview": "How cloudseed is built: a stdlib Python CLI, Terraform stacks per target, Ansible for hosts, a Helm catalog and agent skills.",
    "feature network": "One non-overlapping address space per environment: public and private subnets, NAT egress, flow logs, deny-by-default firewalls.",
    "feature bastion": "A single hardened SSH jump host, reachable only from your IP, with key-only auth, an encrypted disk and Ansible hardening.",
    "feature security-baseline": "Account- and project-wide guard rails, each managed by one environment: CloudTrail, GuardDuty, audit logs, Defender, encryption defaults.",
    "feature state": "Terraform state per environment: a versioned, encrypted bucket or storage account bootstrapped first, or local files.",
    "feature kubernetes": "Managed clusters (EKS / GKE / AKS, private endpoint by default) or RKE2 / kubeadm on VMware, one kubeconfig per environment.",
    "feature platform": "A curated Helm / kustomize catalog in groups, installed in dependency order with values per target and private load balancers.",
    "feature vpn": "An OpenVPN server with per-user profiles, or a Tailscale subnet router, giving your machine a route into the private network.",
    "feature vmware": "Local VMs on VMware Fusion Pro 13+ / Workstation Pro 17+ through cloudseed's own Terraform provider, on a host-only network.",
    "feature provisioning": "After apply, the repository is copied to the hosts over SSH and Ansible hardens them and installs the tools.",
    "feature finops": "Cost estimates from the inventory, actual cloud bills and Kubernetes cost allocation with OpenCost, saved as reports.",
    "feature managed-data": "Databricks and Snowflake through their official CLIs, with a private connection profile per environment.",
    "feature agentic": "An optional agent (built-in, Claude Code, Codex, Gemini or Grok) that drives cloudseed while credentials are kept away from it.",
    "feature reconcile": "Terraform runs survive 'already exists': only objects provably this environment's are imported, and the new plan is approved again.",
    "feature mcp": "cloudseed as an MCP server: one tool per feature plus resources and prompts, over stdio or local HTTP with a token.",
    "feature prereqs": "Cloud resources platform items need (Velero buckets, Karpenter roles, identities) come from the environment's own Terraform stack.",
    "feature fips": "fips_mode=true builds the whole environment for FIPS 140: endpoints, images, hosts, algorithms and a gated platform catalog.",
    "feature chaos": "Chaos Mesh experiments against a canary or your Deployment, with an availability hypothesis and a PASS / FAIL report.",
    "feature dr": "Velero backups to storage the stack creates, restores, schedules, and automated drills that measure the recovery time.",
    "feature scan": "Security scanners and a separate local Well-Architected assessment, with saved reports and explicit verdicts.",
    "feature architecture": "Assess saved configuration and evidence against provider guidance; missing evidence remains unknown and no cloud resources are changed.",
    "feature undo": "A journal of the last fifteen actions per environment (and fifteen global ones, at most five of one kind) with their inverse: cs undo reverts the newest.",
    "feature ui": "A local, token-protected web console where every cloudseed capability is a form and a button, and a \"?\" explains each one.",
    "feature audit": "Every command writes an audit line and a redacted log; inventory.json tracks resources and changes; troubleshoot reads them.",
    "feature dependencies": "Tools installed locally (Homebrew or verified releases), in a container image, or as one self-contained bundle.",
    "topic fips": "FIPS 140 mode: one switch that makes everything in the environment FIPS-capable, or refuses what cannot be.",
    "topic quickstart": "The shortest path from nothing to a working environment: doctor, log in, setup, ssh, status, destroy.",
    "topic security": "The security model: network exposure, host hardening, identity, encryption, logging and how secrets are kept.",
    "topic state": "Where Terraform state lives (a hardened remote bucket or local files) and how to switch between them.",
    "topic envs": "Environments and their working directories: answers, SSH keys, logs, state, outputs, naming and tags.",
    "topic vmware": "Local virtual machines on VMware Fusion Pro / Workstation Pro: the same shape as a cloud environment, on your machine.",
    "topic services": "Optional services per environment (Kubernetes, VPN) switched on with --var or the setup prompts.",
    "topic troubleshooting": "Common failures and their fixes: missing tools, credentials, 'already exists', SSH timeouts, permissions.",
    "topic examples": "Worked examples of common tasks on every target, from the first environment to teardown.",
    "command enable": "Turn on agentic mode, the headliner brief, the MCP server or the local web console.",
    "command disable": "Turn off agentic mode, the headliner brief, the MCP server or the local web console.",
    "command ui": "The local web console: every cloudseed capability as a form and a button (cs ui opens it).",
    "command help": "Help pages: the overview, one page per command and the topic guides.",
    "command finops": "Cost estimates, actual cloud bills and Kubernetes cost allocation (OpenCost), saved as reports.",
    "command explain": "How anything in cloudseed works: features, targets, commands, topics, platform groups and items, setup variables.",
    # (review) where the automatic summary was cut mid-sentence or said too little for a tooltip
    "target aws": "What cs setup aws builds on AWS: a VPC, a hardened bastion and the account baseline, optional EKS, VPN and FIPS, with every variable and output.",
    "target gcp": "What cs setup gcp builds on Google Cloud: a VPC, a hardened bastion and the logging baseline, optional GKE, VPN and FIPS, with every variable and output.",
    "target azure": "What cs setup azure builds on Azure: a VNet with NSGs and a NAT gateway, a hardened bastion, Log Analytics, optional AKS, VPN, FIPS and Defender.",
    "target vmware": "What cs setup vmware builds on your machine: VMs on a host-only network, host and architecture detection, guest OS choices, every variable and output.",
    "command list": "Every environment with its cloud, region, state location, bastion IP and last update.",
    "command doctor": "Checks Terraform, ssh-keygen and the cloud CLIs, their versions, the runtime, container engines and whether credentials were found.",
    "command managed": "Managed data platforms next to your clusters: Databricks and Snowflake through their official CLIs, one connection profile per environment.",
    "command mcp": "cloudseed as an MCP server: every feature is a tool for Claude Code, Claude Desktop, Codex, Cursor, Windsurf, Gemini CLI or VS Code.",
    "command undo": "Undo the newest action (setup changes, installs, node changes, backups), fifteen deep per environment; --global for settings, agents, MCP and UI.",
    "command use": "Select the agent cs agentic runs, and install its CLI and the cloudseed skills for it.",
    "command kubectl": "Run kubectl against the current cluster: the environment's kubeconfig, a bastion tunnel when needed, installed after asking when missing.",
    "command helm": "Run helm against the current cluster: the environment's kubeconfig, a bastion tunnel when needed, installed after asking when missing.",
    "command k9s": "Run k9s against the current cluster: the environment's kubeconfig, a bastion tunnel when needed, installed after asking when missing.",
    "command skill": "The agent skills bundled with cloudseed: list them, show one, or install them for an agent.",
    "group devsecops": "DevSecOps: GitLab + runner and a CI template, NeuVector, Trivy operator, ArgoCD; registries Harbor, Artifactory and Nexus; SonarQube.",
    "group security": "Security / zero trust: Istio (ambient or sidecar, strict mTLS), Falco, Kyverno policies, cert-manager with a cluster CA issuer, External Secrets.",
}


def _as_sentence(text: str, n: int = 160) -> str:
    """A summary as one sentence of at most n characters, ending like one (the tooltips and the index read alike)."""
    text = _fit(text, n - 1)
    return text + "." if text and text[-1] not in ".!?…" else text


MAX_QUERY = 200          # the longest query lookup() takes (the console's GET /api/explain refuses longer ones)
TEXT_WIDTH = 100         # lookup()'s text is laid out like `cs explain ... | cat`
_SECTIONS = (("files", "Implemented in"), ("controls", "Security controls"), ("state", "State and logs"), ("commands", "Commands"))
_CLOUD_NAMES = {"aws": "AWS", "gcp": "GCP", "azure": "Azure", "vmware": "VMware"}
_KIND_HEADINGS = {"feature": "Features", "target": "Targets", "command": "Commands", "topic": "Topics",
                  "group": "Platform groups", "item": "Platform items"}


def _feature_data(name: str) -> dict:
    """A feature page as data: page() renders it for the terminal, lookup() returns it."""
    f = FEATURES[name]
    sections = [{"heading": "How it works", "format": "text", "lines": [" ".join(f["what"].split())]}]
    for key, heading in _SECTIONS:
        if f.get(key):
            sections.append({"heading": heading, "format": "list", "lines": [" ".join(str(x).split()) for x in f[key]]})
    return {"title": TITLES.get(name, name), "summary": SUMMARIES.get("feature " + name) or _sentence(f["what"]), "sections": sections,
            "commands": [" ".join(str(c).split()) for c in f.get("commands", [])]}


def _render_feature(name: str, data: dict, width: int, plain: bool = False) -> str:
    style = (lambda s, *_: s) if plain else ui.style
    dim = (lambda s: s) if plain else ui.dim
    head = f"  {name}" if plain else f"  {ui.style('━━', 'brand')} {ui.style(name, 'bold', 'text')}"
    what, rest = data["sections"][0], data["sections"][1:]
    out = [head, "", "\n".join(_wrap(what["lines"][0], max(40, width), "  ", "  ")), ""]
    for sec in rest:
        out.append(f"  {style(sec['heading'], 'muted')}")
        for x in sec["lines"]:
            rows = _wrap(x, max(24, width - 6), "", "")
            out.append(f"    {style('·', 'brand')} {rows[0]}")
            out += ["      " + r for r in rows[1:]]
        out.append("")
    src = f"  source checkout: {paths.REPO_ROOT}"
    out += [dim(src)] if len(src) <= width else [dim("  source checkout:"), dim(f"  {paths.REPO_ROOT}")]
    return "\n".join(out)


def page(feature: str | None, width: int | None = None) -> str:
    w = width or _width()
    if not feature or feature not in FEATURES:
        head = _wrap("how it is implemented, where its state lives, which commands drive it", max(20, w - 23), "", "")
        lines = [ui.bold("cs explain <feature>") + "   " + ui.dim(head[0])] + ["                       " + ui.dim(h) for h in head[1:]] + [""]
        key_w = max(len(k) for k in FEATURES) + 2
        for k, v in FEATURES.items():
            lines.append(f"  {ui.style(k.ljust(key_w), 'text')} {ui.dim(_fit(v['what'], max(20, w - key_w - 4)))}")
        return "\n".join(lines)
    return _render_feature(feature, _feature_data(feature), w)


# `cs explain <namespace> <name>` picks one meaning of a word that names several things (cli.cmd_explain)
NAMESPACES = ("feature", "target", "topic", "command", "group", "item")


def words() -> list[str]:
    """Every word `cs explain <word>` accepts on its own: features, targets, platform groups and items, help commands
    and topics."""
    from . import help as helpmod, platform as pl
    items = [k for k, v in pl.CATALOG.items() if not v.get("hidden")]
    return list(dict.fromkeys(list(FEATURES) + list(helpmod.CLOUDS) + ["platform"] + list(pl.GROUPS) + items
                              + [c for c in helpmod.COMMANDS if c != "help"] + list(helpmod.TOPICS)))


def suggest(word: str) -> list[str]:
    """'Did you mean' for `cs explain <typo>`: close matches over every explainable name, plus names containing it."""
    import difflib
    pool = words()
    near = difflib.get_close_matches(word, pool, n=3, cutoff=0.6)
    near += [k for k in pool if word and word in k and k not in near][:3]
    return list(dict.fromkeys(near))[:5]


def index(width: int | None = None) -> str:
    """Everything `cs explain` accepts."""
    from . import help as helpmod, platform as pl
    w = width or _width()
    label_w = 13

    def row(label: str, words: list[str], note: str = "") -> list[str]:
        text = "  ".join(words) + (f"   {note}" if note else "")
        rows = _wrap(text, max(30, w - label_w), "", "")
        return [f"  {ui.style(label.ljust(label_w - 2), 'muted')}{rows[0]}"] + [" " * label_w + r for r in rows[1:]]

    commands = [c for c in helpmod.COMMANDS if c not in ("help", "managed")]
    items = [k for k, v in pl.CATALOG.items() if not v.get("hidden")]
    lines = [ui.bold("Everything you can explain"), ""]
    lines += row("features", list(FEATURES))
    lines += row("targets", list(helpmod.CLOUDS), "(what gets built there + every variable)")
    lines += row("commands", commands)
    lines += row("topics", list(helpmod.TOPICS))
    lines += row("platform", ["platform", "|", "platform <group>", "|", "platform <item>"])
    lines += row("groups", list(pl.GROUPS))
    lines += row("items", items)
    lines += row("reference", ["variables <cloud>", "|", "outputs <cloud>", "|", "variable <cloud> <name>"],
                 "(generated from the Terraform code; `<cloud> <name>` works too)")
    lines += row("explicit", ["|".join(NAMESPACES) + " <name>"],
                 "(a bare word is looked up as feature > target > platform group/item > command/topic; "
                 "an 'also:' line names the other matches)")
    lines += row("formats", ["--json"], "(the same page as data: title, summary, sections, commands, also, did_you_mean; "
                                         "the web console's ? buttons and the MCP server read it too)")
    lines.append("")
    lines += [ui.dim(r) for r in _wrap("examples: cs explain kubernetes · cs explain vmware · cs explain topic security · "
                                        "cs explain target vmware · cs explain platform security · cs explain istio · "
                                        "cs explain variables aws · cs explain aws single_nat_gateway · cs explain vpn --json",
                                        max(30, w), "  ", "  ")]
    return "\n".join(lines)


# ---------------------------------------------------------------- text helpers

_SENTENCE_END = re.compile(r"(?<=[a-z0-9)\]'\"`])[.!?](?=\s+[A-Z(`'\"])")
_CMD_RE = re.compile(r"^\s*(?:cloudseed|cs) (\S.*)$")
_ACRONYMS = {w.upper(): w for w in ("AWS", "GCP", "Azure", "VMware", "FIPS", "VPN", "MCP", "UI", "UIs", "DR", "CIS", "STIG", "SSH",
                                     "CLI", "API", "IP", "NAT", "VPC", "DNS", "TLS", "KMS", "EKS", "GKE", "AKS", "IAM", "CRDs",
                                     "VM", "VMs", "OS", "k8s", "Kubernetes", "Terraform", "Ansible", "OpenVPN", "Tailscale")}


def _sentence(text: str, n: int = 160) -> str:
    """The first sentence of a text, at most n characters (a tooltip)."""
    text = " ".join(str(text).split())
    m = _SENTENCE_END.search(text)
    return _fit(text[: m.start() + 1] if m else text, n)


def _heading(line: str) -> str:
    """A help page header as a heading: 'WHAT IT BUILDS' -> 'What it builds', 'GATEWAYS AND UIS' -> 'Gateways and UIs'."""
    base = re.sub(r"\s*\(.*\)\s*$", "", line.strip()) or line.strip()
    out = []
    for i, word in enumerate(base.split()):
        core = word.strip(",.:&/'-")
        if core.upper() in _ACRONYMS:
            out.append(word.replace(core, _ACRONYMS[core.upper()]))
        elif any(ch.isdigit() for ch in word):
            out.append(word)
        else:
            out.append(word.lower() if i else word[:1].upper() + word[1:].lower())
    return " ".join(out)


def _tidy(lines: list[str]) -> list[str]:
    """Trailing spaces, leading/trailing and repeated blank lines dropped; the common indentation removed."""
    out: list[str] = []
    for line in lines:
        if not line.strip():
            if out and out[-1] != "":
                out.append("")
        else:
            out.append(line.rstrip())
    while out and out[-1] == "":
        out.pop()
    ind = min((len(x) - len(x.lstrip(" ")) for x in out if x), default=0)
    return [x[ind:] for x in out]


def _help_sections(text: str, titled: bool = False) -> tuple[str, list[dict]]:
    """(title, sections) of a help page: the usage block (its synopsis lines), what comes before the first header
    ('Overview'), then one section per upper-case header. titled: the first line is the page's title (skill pages)."""
    from . import help as helpmod
    lines = [x.rstrip() for x in text.strip("\n").splitlines()]
    title = ""
    if titled and lines:
        title = lines.pop(0).strip()
    elif lines and helpmod._HEADER_RE.match(lines[0]):
        title = _heading(lines[0])
    sections: list[dict] = []
    if lines and not titled and not lines[0].startswith(" ") and _CMD_RE.match(lines[0]):
        usage = []
        while lines and lines[0].strip():
            usage.append(lines.pop(0))
        sections.append({"heading": "Usage", "format": "text", "lines": usage})
    cur = None
    for line in lines:
        if line and not line[0].isspace() and helpmod._HEADER_RE.match(line):
            heading = _heading(line)
            cur = {"heading": "Overview" if heading == title and not sections else heading, "format": "text", "lines": []}
            sections.append(cur)
        elif cur is None:
            if not line.strip():
                continue
            cur = {"heading": "Overview", "format": "text", "lines": [line]}
            sections.append(cur)
        else:
            cur["lines"].append(line)
    for sec in sections:
        sec["lines"] = _tidy(sec["lines"])
    return title, [sec for sec in sections if sec["lines"]]


def _commands_in(text: str, titled: bool = False, limit: int = 40) -> list[str]:
    """The cloudseed command lines of a help page: its synopsis (the unindented lines it starts with) and every indented
    command (examples, tables), comments and descriptions cut off. Unindented lines further down are prose."""
    lines = text.strip("\n").splitlines()[1 if titled else 0:]
    out: list[str] = []
    usage = not titled
    for i, line in enumerate(lines):
        if not line.strip():
            usage = False
            continue
        m = _CMD_RE.match(line)
        if not m or not (usage or line.startswith(" ")):
            continue
        cmd = re.split(r"\s+#|\s{3,}|\s+·\s+", m.group(1).rstrip())[0].strip()
        for nxt in lines[i + 1:]:              # `cloudseed setup aws -y ... \` goes on on the next line
            if not cmd.endswith("\\"):
                break
            cmd = cmd[:-1].rstrip() + " " + re.split(r"\s+#", nxt.strip())[0].strip()
        if cmd and not cmd.endswith(":") and "cs " + cmd not in out:
            out.append("cs " + cmd)
    return out[:limit]


def _prose(sections: list[dict]) -> str:
    """The first sentence of the first real paragraph of a help page (not a command, bullet, table row or sub-title)."""
    for sec in sections:
        if sec["heading"] == "Usage":
            continue
        para: list[str] = []
        for line in sec["lines"] + [""]:
            if line and not line[0].isspace() and not line.startswith(("-", "*", "#")):
                para.append(line)
                continue
            text = " ".join(para)
            if len(text) >= 40 and " " in text:
                return _sentence(text)
            para = []
    return ""


def _overview_rows() -> dict[str, str]:
    """command -> its one-line description in `cs help` (continuation lines joined)."""
    from . import help as helpmod
    rows: list[list[str]] = []
    for line in helpmod.OVERVIEW.splitlines():
        m = re.match(r"^  (\S(?:.*?\S)?)\s{2,}(\S.*)$", line)
        if m and not line.startswith("   "):
            rows.append([m.group(1), m.group(2)])
        elif rows and line.startswith("     ") and line.strip():
            rows[-1][1] += " " + line.strip()
        else:
            rows.append(["", ""])
    out: dict[str, str] = {}
    for term, desc in rows:
        parts = term.split()
        if not parts or any(p[:1] not in "<[\"" for p in parts[1:]):
            continue          # 'enable ui', 'enable | disable': not one command's row
        for name in parts[0].split("|"):
            out.setdefault(name, desc)
    return out


def _capital(text: str) -> str:
    return text[:1].upper() + text[1:] if text and not text.startswith("cloudseed") else text


def _overview_summary(command: str) -> str:
    """The command's row in `cs help`, without a leading list of subcommands ('a | b | c: what it does')."""
    desc = _overview_rows().get(command, "")
    if " | " in desc or re.match(r"^[a-z-]+,", desc):
        desc = desc.split(": ", 1)[1] if ": " in desc else ""
    return _capital(desc)


# ---------------------------------------------------------------- per-kind data

def _target_topic(cloud: str) -> str:
    return "vmware-skill" if cloud == "vmware" else cloud     # plain `help vmware` is the local-VM topic page


def _target_summary(cloud: str) -> str:
    """The target's skill description (skills/cloudseed-<cloud>/SKILL.md front matter), without the agent routing."""
    if SUMMARIES.get("target " + cloud):
        return SUMMARIES["target " + cloud]
    try:
        text = (paths.REPO_ROOT / "skills" / f"cloudseed-{cloud}" / "SKILL.md").read_text()
    except OSError:
        text = ""
    m = re.search(r"^description:\s*(.+)$", text, re.M)
    desc = re.split(r"\s+Use (?:together )?with ", m.group(1))[0].replace("`", "").strip() if m else ""
    desc = _capital(re.sub(r"^.*? - (?=what )", "", desc))
    return _fit(desc or f"What cloudseed builds on {cloud}, with every variable and output.", 160)


def _help_data(topic: str, sub: str | None, kind: str, name: str) -> dict:
    from . import help as helpmod
    text = helpmod.page(topic, sub)
    title, sections = _help_sections(text)
    if topic in ("variables", "outputs"):
        summary = (f"Every Terraform variable of the {sub} stack with its default, the setup inputs, and what cloudseed "
                   "sets itself." if topic == "variables" else f"Every output of the {sub} stack (cs output {sub} --env <env>).")
    elif kind == "command":
        title = f"cs {name}"
        summary = SUMMARIES.get("command " + name) or _overview_summary(name) or _prose(sections) or title
    else:
        summary = SUMMARIES.get("topic " + name) or _prose(sections) or title
    return {"title": title or name, "summary": _fit(summary, 160), "sections": sections, "commands": _commands_in(text), "text": text}


def _target_data(cloud: str) -> dict:
    from . import help as helpmod
    text = helpmod.page(_target_topic(cloud))
    title, sections = _help_sections(text, titled=True)
    commands = [f"cs setup {cloud}", f"cs explain variables {cloud}", f"cs explain outputs {cloud}"]
    return {"title": title or cloud, "summary": _target_summary(cloud), "sections": sections,
            "commands": commands + [c for c in _commands_in(text, titled=True) if c not in commands],
            "text": text}


def _platform_items(name: str) -> list:
    """What `cs platform info <name>` prints without a cluster, as data: [("panel", title, rows), ("hints", parts)]."""
    from . import platform as pl
    with ui.collecting() as items:
        pl.info(name, None)
    return items


def _plain_platform(items: list) -> str:
    out: list[str] = []
    for item in items:
        if item[0] == "panel":
            rows = item[2]
            kw = max([ui.vis_len(str(r[0])) for r in rows if isinstance(r, tuple)] + [8]) + 1
            out += ["", f"  {ui._strip(item[1])}"]
            for r in rows:
                line = f"{ui._strip(str(r[0])).ljust(kw)} {ui._strip(str(r[1]))}" if isinstance(r, tuple) else ui._strip(str(r))
                out.append(("    " + line).rstrip())
        elif item[0] == "hints":
            out.append("  " + "   ·   ".join(ui._strip(str(p)) for p in item[1]))
    return "\n".join(out)


def _hint_commands(items: list) -> list[str]:
    out = []
    for item in items:
        if item[0] == "hints":
            for part in item[1]:
                cmd = re.sub(r"^[a-z ]+:\s*", "", ui._strip(str(part))).strip()   # 'install: cs platform install x'
                if cmd.startswith("cs ") and cmd not in out:
                    out.append(cmd)
    return out


def _group_sections(group: str) -> list[dict]:
    """What a platform group brings (the lists `cs platform info <group>` shows), full descriptions."""
    from . import platform as pl
    core = [k for k, v in pl.CATALOG.items() if v["group"] == group and not v.get("hidden") and v.get("tier", "core") == "core"]
    extras = [k for k, v in pl.CATALOG.items() if v["group"] == group and not v.get("hidden") and v.get("tier") == "extra"]
    shared = pl.GROUP_EXTRA_MEMBERS.get(group, [])
    deps = pl._group_deps(core, shared, None)

    def line(name: str, tag: str = "") -> str:
        spec = pl.CATALOG[name]
        only = f"  [{'/'.join(spec['only'])} only]" if spec.get("only") else ""
        return f"{name} — {' '.join(spec['desc'].split())}{only}{tag}"

    out = [{"heading": f"Installed by cs platform install {group}", "format": "list", "lines": [line(i) for i in core]}]
    if shared:
        out.append({"heading": "Shared with other groups (installed too)", "format": "list", "lines": [line(i) for i in shared]})
    if deps:
        out.append({"heading": "Dependencies pulled in automatically", "format": "list",
                    "lines": [line(d, f"  (dependency, {where})" if where else "  (dependency)") for d, where in deps]})
    if extras:
        out.append({"heading": "Extras - install by name", "format": "list", "lines": [line(i, "  [extra]") for i in extras]})
    return [s for s in out if s["lines"]]


def _platform_data(name: str) -> dict:
    from . import platform as pl
    items = _platform_items(name)
    if name in pl.GROUPS:
        title, summary, sections = f"Platform group: {name}", SUMMARIES.get("group " + name) or pl.GROUPS[name], _group_sections(name)
    else:
        rows = [r for item in items if item[0] == "panel" for r in item[2] if isinstance(r, tuple)]
        title, summary = f"Platform item: {name}", pl.CATALOG[name]["desc"]
        sections = [{"heading": "Catalog entry", "format": "list",
                     "lines": [f"{ui._strip(str(k))}: {' '.join(ui._strip(str(v)).split())}" for k, v in rows]}]
    return {"title": title, "summary": _fit(summary, 160), "sections": sections, "commands": _hint_commands(items),
            "text": _plain_platform(items)}


def _groups_hint() -> str:
    from . import platform as pl
    return ("  groups: " + "  ".join(pl.GROUPS) + "\n  cs explain platform <group|item>   ·   cs platform list   ·   "
            "cs platform info <group|item>")


def _groups_data() -> dict:
    from . import platform as pl
    return {"title": "", "summary": "", "text": "\n" + _groups_hint(),
            "sections": [{"heading": "Groups", "format": "list", "lines": [f"{g} — {d}" for g, d in pl.GROUPS.items()]}],
            "commands": ["cs explain platform <group|item>", "cs platform list", "cs platform info <group|item>"]}


# ---------------------------------------------------------------- stack variables and setup inputs

def variable_rows(cloud: str) -> dict[str, dict]:
    """Every setting of a target, in the order and with the defaults `cs help variables <cloud>` shows them:
    name -> {name, cloud, source (stack | setup | cloudseed), description, default, how, flag, env, choices, prompt,
    advanced}. Stack variables come from terraform/<cloud>/variables.tf, setup inputs from the adapter's questions;
    'cloudseed' ones are set by cloudseed itself (refused in --var; `how` names the flag)."""
    from . import help as helpmod
    try:
        variables = helpmod._parse_variables(cloud)
    except OSError:
        return {}
    questions = helpmod._cloud_questions(cloud)
    qmap = {q.key: q for q in questions}
    declared = {n for n, _, _ in variables}
    owned = helpmod._refused_vars(cloud, declared, questions)
    computed = dict(helpmod._COMPUTED_DEFAULTS.get(cloud, {}))

    def sources(q) -> list[str]:
        return ([helpmod._question_flag(q)] if helpmod._question_flag(q) else []) + list(q.env)

    for q in questions:
        if "{sources}" in computed.get(q.key, ""):
            computed[q.key] = computed[q.key].replace("{sources}", helpmod._or_list(sources(q)) or "an answer")

    def row(name: str, source: str, description: str, default: str, how: str = "") -> dict:
        q = qmap.get(name)
        choices = [str(c) for c in helpmod._question_choices(q)] if q is not None else []
        return {"name": name, "cloud": cloud, "source": source, "description": " ".join(description.split()),
                "default": str(default), "how": how, "flag": (helpmod._question_flag(q) if q is not None else None),
                "env": list(q.env) if q is not None else [], "choices": choices,
                "prompt": q.prompt.strip() if q is not None else "", "advanced": bool(q.advanced) if q is not None else False}

    out: dict[str, dict] = {}
    for name, desc, default in variables:
        if name not in owned:
            q = qmap.get(name)
            text = desc.replace('\\"', '"') or (helpmod._as_statement(q.prompt) if q is not None else "")
            out[name] = row(name, "stack", text, computed.get(name, default))
    for q in questions:
        if q.key not in declared:
            default = computed.get(q.key) or (helpmod._shown_default(q.default) if not callable(q.default) else "(computed)")
            out[q.key] = row(q.key, "setup", helpmod._as_statement(q.prompt), default)
    for name, desc, default in variables:
        if name in owned:
            out[name] = row(name, "cloudseed", desc.replace('\\"', '"'), default, owned[name])
    return out


_VAR_LABELS = {"stack": "{cloud} stack variable", "setup": "{cloud} setup input (not a Terraform variable)",
               "cloudseed": "{cloud} stack variable set by cloudseed"}


def _variable_data(cloud: str, name: str) -> dict:
    r = variable_rows(cloud)[name]
    desc = r["description"] or f"The {name} setting of the {cloud} stack."
    details: list[tuple[str, str]] = []
    commands: list[str] = []
    if r["source"] == "cloudseed":
        details.append(("set by", f"cloudseed: {r['how']} (refused in --var)"))
        tail = f"Set by cloudseed: {_fit(r['how'], 70)}"
    else:
        default = "none" if r["default"] in ("-", "") else r["default"]
        details.append(("default", default))
        how = f"cs setup {cloud} {r['flag']} <value>" if r["flag"] else f"cs setup {cloud} --var {name}=<value>"
        details.append(("set with", how))
        commands.append(how)
        tail = f"Default: {_fit(default, 60)}"
    if r["choices"]:
        details.append(("one of", ", ".join(r["choices"])))
    if r["prompt"]:
        details.append(("setup asks", r["prompt"] + ("   (with --advanced)" if r["advanced"] else "")))
    if r["env"]:
        details.append(("read from", ", ".join(r["env"])))
    commands.append(f"cs explain variables {cloud}")
    tail += "" if tail.endswith(("…", ".")) else "."
    lead = _fit(desc, 159 - len(tail))
    summary = (lead if lead.endswith(("…", ".", "!", "?")) else lead + ".") + " " + tail
    label = _VAR_LABELS[r["source"]].format(cloud=cloud)
    return {"title": f"{name} ({label})", "summary": _fit(summary, 160), "label": label, "description": desc,
            "details": details, "commands": commands,
            "sections": [{"heading": "What it sets", "format": "text", "lines": [desc]},
                         {"heading": "Details", "format": "list", "lines": [f"{k}: {v}" for k, v in details]}]}


def _render_variable(cloud: str, name: str, width: int, plain: bool = False) -> str:
    d = _variable_data(cloud, name)
    style = (lambda s, *_: s) if plain else ui.style
    head = f"  {name}   {d['label']}" if plain else \
        f"  {ui.style('━━', 'brand')} {ui.style(name, 'bold', 'text')}   {ui.dim(d['label'])}"
    out = [head, "", "\n".join(_wrap(d["description"], max(40, width), "  ", "  ")), ""]
    kw = max(len(k) for k, _ in d["details"]) + 2
    for k, v in d["details"]:
        rows = _wrap(v, max(24, width - kw - 4), "", "")
        out.append(f"  {style(k.ljust(kw), 'muted')}{rows[0]}")
        out += [" " * (kw + 2) + r for r in rows[1:]]
    return "\n".join(out)


def _variable_data_step(cloud: str, name: str) -> dict:
    d = _variable_data(cloud, name)
    return {"title": d["title"], "summary": d["summary"], "sections": d["sections"], "commands": d["commands"],
            "text": _render_variable(cloud, name, TEXT_WIDTH, plain=True)}


# ---------------------------------------------------------------- resolution (one for the terminal and for data)

def also_for(word: str, *shown: str) -> list[dict]:
    """The other things a word names (vmware: feature, target and topic; security: group and topic), minus the kinds
    already shown: [{kind, name, query, cli}]."""
    from . import help as helpmod, platform as pl
    seen = set(shown) | ({"platform"} if set(shown) & {"group", "item"} else set())
    out: list[dict] = []

    def add(kind: str, query: str) -> None:
        out.append({"kind": kind, "name": word, "query": query, "cli": "cs explain " + query})

    if "feature" not in seen and word in FEATURES:
        add("feature", f"feature {word}")
    if "target" not in seen and word in helpmod.CLOUDS:
        add("target", f"target {word}")
    if "platform" not in seen and (word in pl.GROUPS or word in pl.CATALOG):
        add("group" if word in pl.GROUPS else "item", f"platform {word}")
    # a command's page already carries its topic (help.page merges them): the topic link would show the same page again
    if "topic" not in seen and word in helpmod.TOPICS and word not in helpmod.COMMANDS:
        add("topic", f"topic {word}")
    if "command" not in seen and word in helpmod.COMMANDS:
        add("command", f"command {word}")
    return out


def print_also(entries: list[dict]) -> None:
    """`  also: cs explain ...   ·   cs explain ...`, wrapped to the terminal, never inside one command."""
    if not entries:
        return
    width, lines, cur = max(40, ui.width() - 2), [], "  also: "
    for e in entries:
        piece = e["cli"] if cur.endswith(": ") else "   ·   " + e["cli"]
        if len(cur) + len(piece) > width and not cur.endswith(": "):
            lines.append(cur)
            cur = "        " + e["cli"]
        else:
            cur += piece
    for line in lines + [cur]:
        print(ui.dim(line))


def _ns_names(ns: str) -> list[str]:
    from . import help as helpmod, platform as pl
    pools = {"feature": FEATURES, "target": helpmod.CLOUDS, "topic": helpmod.TOPICS, "command": helpmod.COMMANDS,
             "group": pl.GROUPS, "item": pl.CATALOG}
    return [k for k in pools[ns] if not (ns == "item" and pl.CATALOG[k].get("hidden"))]


def _close(word: str, pool, prefix: str = "", cutoff: float = 0.6) -> list[str]:
    import difflib
    return [prefix + n for n in difflib.get_close_matches(word, list(pool), n=3, cutoff=cutoff)]


def _resolve(words_: list[str]) -> dict:
    """What `cs explain <words>` shows: {kind, name, query, steps, also, error, near}. `steps` are rendered by show()
    for the terminal and by lookup() as data. error (and near: queries that do resolve) when nothing matches; the
    messages are the CLI's."""
    from . import help as helpmod, platform as pl
    ws = _query_words(words_)      # `cs explain "platform security"` = two words
    res = {"kind": "", "name": "", "query": " ".join(ws), "steps": [], "also": [], "error": "", "near": []}

    def found(kind: str, name: str, steps: list, also: list | None = None) -> dict:
        res.update(kind=kind, name=name, steps=steps, also=also or [])
        return res

    def fail(message: str, near: list[str] | None = None) -> dict:
        res.update(error=message, near=list(dict.fromkeys(near or []))[:5])
        return res

    if not ws:
        return found("index", "", [("index",)])
    head, rest = ws[0], ws[1:]
    clouds = helpmod.CLOUDS
    if head in NAMESPACES:     # explicit: cs explain topic security · target vmware · feature platform · group chaos
        pool = _ns_names(head)
        if not rest:
            return fail(f"cs explain {head} <name>. {head.capitalize()}s: {', '.join(pool)}")
        name = rest[0]
        if name not in pool and not (head == "item" and name in pl.CATALOG):
            return fail(f"No {head} '{name}'. {head.capitalize()}s: {', '.join(pool)}", _close(name, pool, head + " "))
        shown = (head, "command", "topic") if head in ("topic", "command") and name in helpmod.COMMANDS else (head,)
        if head == "feature":
            steps = [("feature", name)]
        elif head == "target":
            steps = [("target", name)]
        elif head in ("topic", "command"):
            steps = [("help", name, rest[1] if len(rest) > 1 else None)]
        else:
            steps = [("platform", name)]
        return found(head, name, steps, also_for(name, *shown))
    if head == "variable":       # cs explain variable <cloud> <name>
        usage = f"cs explain variable <{'|'.join(clouds)}> <name>"
        if not rest or rest[0] not in clouds:
            return fail(usage + (f"  ('{rest[0]}' is not a target)" if rest else ""),
                        _close(rest[0], clouds, "variable ") if rest else [])
        cloud = rest[0]
        rows = variable_rows(cloud)
        if len(rest) < 2 or rest[1] not in rows:
            near = _close(rest[1], rows) if len(rest) > 1 else []
            what = (f"No {cloud} variable '{rest[1]}'" + (f" - did you mean {' or '.join(near)}?" if near else ".")) if len(rest) > 1 \
                else usage + "."
            return fail(f"{what}  Every one: cs explain variables {cloud}", [f"variable {cloud} {n}" for n in near])
        return found("variable", f"{cloud} {rest[1]}", [("variable", cloud, rest[1])], _variable_also(cloud))
    if head == "platform":
        if not rest:
            return found("feature", "platform", [("feature", "platform"), ("groups",)], also_for("platform", "feature", "platform"))
        pool = list(pl.GROUPS) + [k for k, v in pl.CATALOG.items() if not v.get("hidden")]
        for n in rest:
            if n not in pl.GROUPS and n not in pl.CATALOG:
                near = _close(n, pool, cutoff=0.7)
                return fail(f"Unknown platform group or item '{n}'" + (f" - did you mean {' or '.join(near)}?" if near else ".")
                            + "  See: cs platform list", ["platform " + x for x in near])
        kind = "group" if rest[0] in pl.GROUPS else "item"
        return found(kind, " ".join(rest), [("platform", n) for n in rest], also_for(rest[0], "platform") if len(rest) == 1 else [])
    if head in ("variables", "outputs"):
        cloud = rest[0] if rest else None
        if cloud not in clouds:
            return fail(f"cs explain {head} <{'|'.join(clouds)}>" + (f"  ('{cloud}' is not a target)" if cloud else ""),
                        _close(cloud, clouds, head + " ") if cloud else [])
        other = "outputs" if head == "variables" else "variables"
        return found("topic", f"{head} {cloud}", [("help", head, cloud)],
                     [{"kind": "topic", "name": f"{other} {cloud}", "query": f"{other} {cloud}", "cli": f"cs explain {other} {cloud}"},
                      {"kind": "target", "name": cloud, "query": f"target {cloud}", "cli": f"cs explain target {cloud}"}])
    if head in clouds and rest and rest[0] in variable_rows(head):     # cs explain aws single_nat_gateway
        return found("variable", f"{head} {rest[0]}", [("variable", head, rest[0])], _variable_also(head))
    if head in FEATURES:
        if head in clouds:     # vmware: the feature page and the target page (what is built, every variable)
            return found("feature", head, [("feature", head), ("blank",), ("target", head)], also_for(head, "feature", "target"))
        return found("feature", head, [("feature", head)], also_for(head, "feature"))
    if head in clouds:
        return found("target", head, [("target", head)], also_for(head, "target"))
    if head in pl.GROUPS or head in pl.CATALOG:
        return found("group" if head in pl.GROUPS else "item", head, [("platform", head)], also_for(head, "platform"))
    if head in helpmod.COMMANDS or head in helpmod.TOPICS:
        kind = "command" if head in helpmod.COMMANDS else "topic"
        return found(kind, head, [("help", head, rest[0] if rest else None)], also_for(head, kind))
    near = suggest(head)
    return fail(f"Nothing to explain for '{head}'. " + (f"Did you mean: {', '.join(near)}? " if near else "") + "See: cs help explain", near)


def _variable_also(cloud: str) -> list[dict]:
    return [{"kind": "topic", "name": f"variables {cloud}", "query": f"variables {cloud}", "cli": f"cs explain variables {cloud}"},
            {"kind": "target", "name": cloud, "query": f"target {cloud}", "cli": f"cs explain target {cloud}"}]


def resolve(words_: list[str]) -> dict:
    """Public form of the resolution (cli.cmd_explain): see _resolve."""
    return _resolve(words_)


def show(res: dict) -> None:
    """Print a resolution for the terminal, styled and laid out the way `cs explain` always has."""
    from . import help as helpmod, platform as pl
    for step in res["steps"]:
        kind = step[0]
        if kind == "index":
            print(page(None))
            print()
            print(index())
        elif kind == "feature":
            print(page(step[1]))
        elif kind == "target":
            helpmod.print_page(_target_topic(step[1]), None)
        elif kind == "help":
            helpmod.print_page(step[1], step[2])
        elif kind == "platform":
            pl.info(step[1], None)
        elif kind == "groups":
            print()
            print(ui.dim(_groups_hint()))
        elif kind == "variable":
            print(_render_variable(step[1], step[2], _width()))
        elif kind == "blank":
            print()
    print_also(res["also"])


def _step_data(step: tuple) -> dict:
    kind = step[0]
    if kind == "index":
        return _index_data()
    if kind == "feature":
        data = _feature_data(step[1])
        return dict(data, text=_render_feature(step[1], data, TEXT_WIDTH, plain=True))
    if kind == "target":
        return _target_data(step[1])
    if kind == "help":
        from . import help as helpmod
        return _help_data(step[1], step[2], "command" if step[1] in helpmod.COMMANDS else "topic", step[1])
    if kind == "platform":
        return _platform_data(step[1])
    if kind == "groups":
        return _groups_data()
    if kind == "variable":
        return _variable_data_step(step[1], step[2])
    return {"title": "", "summary": "", "sections": [], "commands": [], "text": ""}     # blank


def _index_data() -> dict:
    sections: list[dict] = []
    by_kind: dict[str, list[str]] = {}
    for n in names():
        cloud = n["name"].split()[0]
        heading = (f"{_CLOUD_NAMES.get(cloud, cloud)} variables" if n["kind"] == "variable"
                   else _KIND_HEADINGS.get(n["kind"], n["kind"].capitalize()))
        by_kind.setdefault(heading, []).append(f"{n['name']} — {n['summary']}")
    for heading, lines in by_kind.items():
        sections.append({"heading": heading, "format": "list", "lines": lines})
    text = ui._strip(page(None, TEXT_WIDTH)) + "\n\n" + ui._strip(index(TEXT_WIDTH))
    return {"title": "Everything you can explain", "sections": sections, "text": text,
            "summary": "Features, targets, commands, topics, platform groups and items, and every setup variable cloudseed can explain.",
            "commands": ["cs explain kubernetes", "cs explain vmware", "cs explain topic security", "cs explain target vmware",
                         "cs explain platform security", "cs explain istio", "cs explain variables aws",
                         "cs explain aws single_nat_gateway", "cs explain vpn --json"]}


def _query_words(words_) -> list[str]:
    """The caller's words as a query: split on whitespace, secrets masked, then lower-cased. Masked FIRST: the
    redactor's token patterns are case-sensitive (AKIA..., -----BEGIN ... PRIVATE KEY-----, AIza..., GOCSPX-...), so a
    lower-cased key would slip past the redaction of everything that echoes the words back (query, cli and error of
    lookup(), the CLI's "Nothing to explain for ..." line)."""
    text = " ".join(str(x) for x in words_)
    try:
        text = secrets.redact(text)
    except Exception:  # noqa: BLE001 - nothing that could not be checked is echoed
        return [secrets.REDACTED] if text.split() else []
    return [w.lower().replace(secrets.REDACTED.lower(), secrets.REDACTED) for w in text.split()]


def _empty(query: str) -> dict:
    return {"query": query, "found": False, "kind": "", "name": "", "title": "", "summary": "", "sections": [], "text": "",
            "commands": [], "also": [], "did_you_mean": [], "cli": ("cs explain " + query).rstrip(), "error": ""}


def lookup(query=None) -> dict:
    """The structured `cs explain` page of a query: "" (the index), a bare word (vpn, aws, setup, velero), a namespaced
    form (target vmware, group security, item velero, command destroy, topic envs, feature dr, variable aws
    single_nat_gateway), `platform <group|item>`, `variables|outputs <cloud>` or `<cloud> <variable>` - resolved exactly
    like the CLI. A list of words is taken as they are (the CLI's argv); secrets in them are masked before anything
    echoes them (_query_words). Pure: no subprocess, no network, no ANSI; never raises. Keys (always present): query,
    found, kind, name, title, summary (<= 160 chars), sections [{heading, format: list|text, lines}], text (the page as
    `cs explain` prints it, plain), commands, also [{kind, name, query, cli}], did_you_mean (queries that resolve),
    cli, error ('' when found)."""
    if isinstance(query, (list, tuple)):
        ws = [str(w) for w in query]
    else:
        ws = str(query or "").split()
    raw = " ".join(" ".join(ws).split())
    if len(raw) > MAX_QUERY:
        out = _empty(_fit(" ".join(_query_words([raw])), 40))
        out["error"] = f"query too long (max {MAX_QUERY} characters)"
        return out
    try:
        res = _resolve(ws)
        out = _empty(res["query"])
        if res["error"]:
            out.update(error=res["error"], did_you_mean=res["near"])
            return out
        parts = [_step_data(s) for s in res["steps"]]
        main = parts[0]
        sections, commands = [], []
        for p in parts:
            sections += p["sections"]
            commands += [c for c in p["commands"] if c not in commands]
        text = "\n".join(p["text"] for p in parts)
        if res["also"]:
            text += "\n  also: " + "   ·   ".join(e["cli"] for e in res["also"])
        out.update(found=True, kind=res["kind"], name=res["name"], title=main["title"], summary=_as_sentence(main["summary"]),
                   sections=sections, text=ui._strip(text).strip("\n").rstrip() + "\n", commands=commands, also=res["also"])
        if res["kind"] == "variable":
            out["cloud"] = res["name"].split()[0]
        return out
    except (Exception, ui.Abort) as e:  # noqa: BLE001 - documentation must never take a caller down
        query = " ".join(_query_words([raw]))
        out = _empty(query)
        out["error"] = f"cannot explain '{query}': {type(e).__name__}: {e}"
        return out


_NAMES_CACHE: list[dict] = []


def names() -> list[dict]:
    """Every explainable thing once: [{kind, name, summary, query}]. `query` is what lookup() / `cs explain` take for
    exactly that entry: the bare word when it resolves to it, else the namespaced form (group finops, command vpn,
    variable aws single_nat_gateway). Built once per process (it is static documentation)."""
    if not _NAMES_CACHE:
        _NAMES_CACHE[:] = _build_names()     # replaced whole: two threads building at once cannot duplicate entries
    return [dict(n) for n in _NAMES_CACHE]


def _bare_kind(word: str) -> str:
    from . import help as helpmod, platform as pl
    if word in FEATURES or word == "platform":
        return "feature"
    if word in helpmod.CLOUDS:
        return "target"
    if word in pl.GROUPS:
        return "group"
    if word in pl.CATALOG:
        return "item"
    if word in helpmod.COMMANDS:
        return "command"
    return "topic" if word in helpmod.TOPICS else ""


def _build_names() -> list[dict]:
    from . import help as helpmod, platform as pl
    out: list[dict] = []
    seen: set = set()

    def add(kind: str, name: str, summary: str, query: str | None = None) -> None:
        q = query or (name if _bare_kind(name) == kind else f"{kind} {name}")
        if q not in seen:
            seen.add(q)
            out.append({"kind": kind, "name": name, "summary": _as_sentence(summary), "query": q})

    def help_summary(word: str, kind: str) -> str:
        try:
            return _help_data(word, None, kind, word)["summary"]
        except Exception:  # noqa: BLE001
            return word

    for f in FEATURES:
        add("feature", f, _feature_data(f)["summary"])
    for c in helpmod.CLOUDS:
        add("target", c, _target_summary(c))
    for c in helpmod.COMMANDS:
        if c != "help":
            add("command", c, help_summary(c, "command"))
    for t in helpmod.TOPICS:
        if t not in helpmod.COMMANDS:     # deps, agentic, destroy: the command's page already carries the topic
            add("topic", t, help_summary(t, "topic"))
    for c in helpmod.CLOUDS:
        add("topic", f"variables {c}", f"Every Terraform variable of the {c} stack with its default, the setup inputs, and "
            "what cloudseed sets itself.", f"variables {c}")
        add("topic", f"outputs {c}", f"Every output of the {c} stack (cs output {c} --env <env>).", f"outputs {c}")
    for g, desc in pl.GROUPS.items():
        add("group", g, SUMMARIES.get("group " + g) or desc)
    for i, spec in pl.CATALOG.items():
        if not spec.get("hidden"):
            add("item", i, spec["desc"])
    for c in helpmod.CLOUDS:
        for v in variable_rows(c):
            try:
                summary = _variable_data(c, v)["summary"]
            except Exception:  # noqa: BLE001
                summary = v
            add("variable", f"{c} {v}", summary, f"variable {c} {v}")
    return out
