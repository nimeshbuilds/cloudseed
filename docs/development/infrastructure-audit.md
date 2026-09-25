---
title: Infrastructure and runtime audit
description: Source-grounded review of cloudseed's Terraform stacks, host provisioning, VMware provider, packaging, verification limits, and recommended infrastructure work.
---

# Infrastructure and runtime audit

Reviewed on 2026-09-24 against source commit `a6c6e7c12447d51c6c0c11fff18320dc2ddb0295`. This report covers the checked-in infrastructure and provisioning implementation. It distinguishes source behavior from things demonstrated by a live deployment. No cloud resources, VMware machines, credentials, or host configuration were changed during this review. Changes made alongside this report should be assessed separately from the original-source findings below.

The project already has substantial implementation: four deployment targets, seven Terraform roots, 47 Terraform source files, ten Ansible roles, and a custom Go provider. The most valuable next infrastructure work is lifecycle reliability, repeatable versions, and live evidence for the existing cloud paths. Adding another large catalog or cloud target before those foundations would increase the verification burden.

## End-to-end execution

1. The CLI and cloud adapter select an environment, collect credentials and configuration, validate inputs, and render an environment root under its working directory. That root calls the generic module in `terraform/<target>`. The checked-in Terraform is not the environment's working state.
2. Cloud remote state has its own bootstrap root. AWS creates an S3 bucket; GCP creates a GCS bucket; Azure creates a storage account and container. The environment then uses that backend. VMware uses local state and a locally built provider.
3. `cloudseed/tf.py` runs Terraform initialization, plan, output inspection, and apply. It supplies the local-provider mirror where needed, handles provider-cache/checksum problems, and integrates reconciliation and approval checks. Terraform creates networking, identity, VMs, managed clusters, and optional cloud prerequisites for platform add-ons.
4. `cloudseed/provision.py` builds an allow-listed source archive, transfers it to bastion/VPN hosts over SSH, and invokes `ansible/bootstrap.sh`. That script creates a private Ansible virtualenv on each host and runs its playbook locally with privilege escalation. Kubernetes on VMware is different: Ansible runs on the workstation against generated node inventory.
5. After provisioning, separate Python subsystems use cloud CLIs, SSH, kubectl, Helm, and scanner CLIs for cluster access, platform installation, backups, restore drills, chaos, compliance, and operations. Those are not all Terraform resources.
6. Destruction combines Terraform with target-specific cleanup. Shared account/project/subscription settings have ownership implications. VMware network cleanup cannot be implemented solely through its REST provider and has a separate host-side path.

Principal boundaries: `cloudseed/clouds/`, `cloudseed/tf.py`, `cloudseed/provision.py`, `cloudseed/localvm.py`, `terraform/`, `ansible/`, and `providers/vmdesktop/`.

## Runtime and packaging inventory

| Runtime | What runs where | Dependencies and practical limits |
|---|---|---|
| Local source checkout | `bin/cloudseed` launches the Python package on the workstation. The CLI uses the standard library. | Python 3.9+; Terraform 1.10+; SSH; cloud CLIs and Kubernetes tools when their commands need them. Installation links the checkout onto PATH, so the checkout must remain present. |
| Local tool installation | `cloudseed/deps.py` and `cloudseed/services.py` install tools or groups, using Homebrew, vendor releases, isolated virtualenvs, or OS package managers. | Tool-specific requirements still apply. These installers are an orchestration convenience, not an offline dependency set. |
| Docker/Podman | `cloudseed/container.py` reexecutes a command in `cloudseed:local`, sets local runtime inside the container, and mounts environment state at the same absolute path. | Requires a running engine. The image contains Python, Terraform, AWS CLI, Google Cloud CLI and GKE auth plugin, Azure CLI, kubectl, Helm, OpenSSH, Go, qemu-img, and basic tools. It does not preinstall every optional scanner or application CLI. VMware always uses the host. |
| PyInstaller bundle | `scripts/build-bundle.sh` embeds Python code, data directories, and a downloaded Terraform binary into `dist/cloudseed-<os>-<arch>`. | Build on the target OS/architecture. Cloud CLIs, Helm, kubectl, VMware, and other external tools are not all embedded. Building requires network access for Terraform, pip, and PyInstaller. |
| Bastion/VPN provisioning | `ansible/bootstrap.sh` runs on each target host; Ansible itself lives in `~/.cloudseed-ansible`. | Controller Python 3.10+ on that host, Ansible core >=2.16, apt or dnf, package-network access, sudo, and SSH. AL2023 can receive an additional Python interpreter. |
| VMware cluster provisioning | Workstation Ansible drives the private node IPs. | Local control-node support plus reachable Ubuntu/Debian guests. Windows detection remains experimental; native Windows environment changes are refused until locking and control-node support exist. |
| Terraform VMware provider | Native Go executable loaded from `registry.local/cloudseed/vmdesktop` filesystem mirror. | Go 1.25+ to build; Fusion/Workstation tools to execute; REST listener for network operations. It is not a vSphere provider. |

The container runs as root internally and intentionally mounts cloud credential directories and environment workdirs writable. Credential values are passed through environment inheritance, not expanded into command-line arguments. Platform-specific installed tools are isolated under `container-linux-<arch>` so Linux binaries do not replace workstation binaries. Rootful Docker on Linux uses the entrypoint to return new/changed root-owned files to the host UID/GID. This makes container execution convenient, but it should not be presented as a security sandbox around untrusted commands.

The Docker base uses a digest, and named core-tool versions are build arguments. However, Google Cloud CLI and ordinary apt dependencies are floating. Bundle builds default to the latest Terraform release and install unpinned PyInstaller. The Ansible bootstrap has no upper Ansible version bound. Therefore neither the container nor bundle is fully reproducible from the repository revision alone.

Source: `Dockerfile`, `.dockerignore`, `scripts/build-bundle.sh`, `scripts/container-entrypoint.sh`, `scripts/install.sh`, `cloudseed/container.py`, `ansible/bootstrap.sh`, and `docs/guides/dependencies-and-runtimes.md`.

## Terraform roots and cloud features

All roots require Terraform >=1.10. AWS constrains `hashicorp/aws` to `~> 6.0`; GCP permits Google provider >=6 and <8; the Azure main stack requires AzureRM >=4.65 and <5, while Azure bootstrap allows >=4.9 and <5. VMware uses the local provider `~> 0.1`. These are ranges rather than a single complete dependency manifest.

| Root | Main contents | Native mocked test files |
|---|---|---:|
| `terraform/aws` | Network, bastion, KMS, account/regional baseline, EKS, VPN, platform IAM/storage | 3 |
| `terraform/aws-bootstrap` | Versioned encrypted S3 state bucket and TLS-only policy | 0 |
| `terraform/gcp` | VPC, bastion, project logging, GKE, VPN, platform identities/storage, naming helpers | 1 |
| `terraform/gcp-bootstrap` | Versioned private GCS state bucket | 1 |
| `terraform/azure` | Resource group, VNet, bastion, logging/Defender, AKS, VPN, platform identities/storage | 1 |
| `terraform/azure-bootstrap` | Resource group, LRS storage account, private state container | 0 |
| `terraform/vmware` | Host-only network, gateway bastion, workload VMs, Kubernetes node VMs | 0 |

### AWS

The network creates a VPC, internet gateway, public and private subnets across two AZs by default, optional isolated data subnets, NAT gateways, separate route tables, an empty default security group, and CloudWatch VPC flow logs. `single_nat_gateway=true` is the default: the network spans AZs but its default egress topology has one NAT gateway. `subnet_stride` and AZ handling try to preserve existing subnet addresses when changing topology.

The bastion is Amazon Linux 2023 selected through SSM, with an Elastic IP, SSH allow-list, SSM instance role, IMDSv2 required, hop limit one, and KMS-encrypted gp3 root storage. Its AMI and initial user data are ignored for later replacement planning; patching is the host-provisioning path, not automatic AMI replacement on every upstream release.

The KMS module provides a rotating environment key and service policies. The security baseline covers S3 account public-access blocking, IAM password policy, default EBS encryption, IAM Access Analyzer, GuardDuty, encrypted multi-region CloudTrail, and optional Security Hub/AWS Config integration. Account-wide and regional ownership are separately controllable. A second environment must not independently manage the same shared baseline resources.

EKS has a private API by default, optionally constrained public API access, encrypted secrets, all five control-plane log categories, cluster access entries, an on-demand managed node group, and VPC CNI/kube-proxy/CoreDNS/EBS CSI add-ons. Node desired size is deliberately ignored after creation so Terraform does not undo API/autoscaler scaling. IAM roles for platform service accounts cover controllers including external secrets, DNS, autoscaling, load balancing, and storage; Velero and Karpenter prerequisites are created on demand. External secrets defaults to environment-prefixed secret/parameter access.

The optional VPN uses its own Ubuntu EC2 host and Elastic IP, SSH and UDP rules, disabled source/destination checking for routing, and access to private workloads. OpenVPN and Tailscale differ at the Ansible layer. FIPS mode changes EKS to Bottlerocket FIPS images, enables the bastion's FIPS mode, and uses the project's separate provider/backend endpoint handling. The code supports commercial AWS and GovCloud; it explicitly warns/refuses unsupported partitions through Terraform checks and CLI validation.

Source: `terraform/aws/main.tf`, `terraform/aws/variables.tf`, and every subdirectory of `terraform/aws/modules/`.

### GCP

The stack enables required APIs without disabling them on destroy, creates a custom regional-mode VPC, public/private subnetworks, Private Google Access, sampled flow logs, a Cloud Router, and private-subnet Cloud NAT. Firewall rules allow operator SSH to the bastion, bastion SSH to private targets, private internal traffic, and a logged ingress deny.

The bastion defaults to Debian 12 and `e2-micro`, has a static external IP, dedicated service account, Shielded VM settings, and either an explicit metadata SSH key or optional OS Login IAM. The names module handles service-account, cluster, firewall, and storage naming constraints.

GKE is a **zonal** cluster and node pool. It uses private nodes and a private API by default, VPC-native networking, Dataplane V2, Workload Identity, shielded COS/containerd nodes, control-plane/system/workload logs, managed Prometheus, and the REGULAR release channel. The configured Kubernetes version is a minimum; the release channel can advance it. Nodes auto-repair and auto-upgrade. Requested node count also contributes to the autoscaling floor.

The project baseline sets `_Default` log retention and optionally authoritative `allServices` Data Access audit configuration. The CLI has keep-on-destroy handling for shared project settings. External secrets receives project-level `roles/secretmanager.secretAccessor`; external DNS receives DNS privileges, and Velero receives a dedicated bucket/identity when requested. The external-secrets scope is broader than AWS's default prefix policy.

The VPN is a separate compute instance. Its route set includes the GKE control-plane CIDR outside the main VPC allocation. FIPS host selection uses Ubuntu Pro FIPS variants; the GKE node pool continues to use COS/containerd. GKE's image choice and a FIPS flag should not be interpreted as independent certification of all workloads.

Source: `terraform/gcp/main.tf`, `terraform/gcp/variables.tf`, and every subdirectory of `terraform/gcp/modules/`.

### Azure

The stack creates an environment resource group, VNet, public/private subnets with default outbound access disabled, separate NSGs, and a Standard NAT gateway for private egress. NSGs explicitly restore load-balancer probes and permit the relevant private/bastion traffic before denying ingress. There is no VNet flow-log resource in this stack; that gap is already on the roadmap.

The bastion defaults to an Ubuntu 24.04 VM with Standard public IP, SSH-key-only authentication, Secure Boot, vTPM, a system-assigned identity, and Standard SSD storage. FIPS mode selects the Ubuntu Pro FIPS marketplace image and manages subscription-level marketplace terms.

AKS uses the Free tier, a private API by default, a public DNS name resolving to the private API address for VPN/tunnel reachability, Azure CNI Overlay, Azure network policy, NAT-gateway egress, OIDC/workload identity, Azure Policy, a managed identity, and an autoscaling AzureLinux system pool. Pool rotation uses a temporary pool name. The NSG allows pod-to-pod overlay addresses and bastion ingress-service access. Logs go to the environment's Log Analytics workspace. Node count is ignored after creation while min/max govern the autoscaler.

External secrets gets a federated identity, but users must grant it the relevant Key Vault permissions. External DNS and Velero have cloud prerequisites; Velero adds storage and scoped role assignments. The optional VPN has its own VM and public IP.

The baseline always creates Log Analytics, optionally exports subscription Activity Logs, and optionally enables Defender plans for VMs and storage. Those pricing settings and marketplace terms affect the subscription, not only the environment. Defender subplan/extensions are deliberately ignored after creation to preserve administrator changes.

Source: `terraform/azure/main.tf`, `terraform/azure/variables.tf`, and every subdirectory of `terraform/azure/modules/`.

### Remote state

AWS bootstrap uses S3 versioning, KMS server-side encryption, ownership enforcement, public-access blocks, a TLS-only policy, 90-day noncurrent-version expiry, and native S3 lockfiles supplied by the runtime backend configuration. GCP bootstrap uses uniform bucket access, enforced public-access prevention, versioning, and retention of recent archived versions. Azure bootstrap uses HTTPS/TLS 1.2, a private container, LRS replication, blob versioning, and 30-day blob/container soft deletion.

AWS and GCP bootstrap buckets use `force_destroy=true`. This permits an explicitly requested bootstrap teardown to delete versions along with the bucket. There is no Terraform `prevent_destroy` barrier in these bootstrap resources. A production retention mode, external backend adoption, and independent state recovery/export would be useful additions. The project already has approval and teardown sequencing; this finding is about durable retention policy, not evidence that state is deleted during an ordinary apply.

## VMware target and Go provider

`cloudseed/localvm.py` detects Fusion/Workstation, prepares its tools, downloads checksum-verified Ubuntu 24.04/22.04 or Debian 12 cloud images, converts qcow2/raw images where necessary, builds the provider, writes a filesystem mirror configuration, manages its own `vmrest` process/credentials, and performs additional cleanup. The default guest is Ubuntu 24.04. Intel/AMD and ARM guests use architecture-specific images. Debian deliberately uses generic rather than genericcloud images so the NoCloud seed CD-ROM is visible.

The Terraform model is a gateway bastion with a NAT NIC and private NIC, optional private workload VMs, and optional private Kubernetes node VMs. The bastion forwards/NATs private traffic. The static plan assigns the bastion host `.2`, workloads from `.10`, control planes `.20` through `.39`, and workers from `.40`, capped before the VMware DHCP pool and subnet boundary. Kubernetes nodes are keyed by `cp1`/`wk1` names, so adding control planes does not shift worker indexes. Legacy cloud-init preservation avoids rebuilding existing bastion/workload VMs merely because bundled templates changed.

| Provider element | Behavior |
|---|---|
| `vmdesktop_host` data source | Host product/version/guest architecture. |
| `vmdesktop_network` | Lists networks through REST, adopts matching subnet/type, rejects overlap, or creates a vmnet. Supports import. Reads subnet/type drift. VMware's REST API cannot remove or mutate these network settings through this implementation; deletion forgets the resource and reports retention. |
| `vmdesktop_vm` | Clones a base VMDK, grows storage, renders VMX, attaches NoCloud ISO and guestinfo metadata, starts via `vmrun`, discovers addresses from DHCP leases/Tools, and exposes state. |
| In-place VM changes | CPU, memory, running state, and disk growth. Hardware changes stop/restart the VM. |
| VM replacement changes | Name/path/base disk/guest type/firmware, disk shrink, NIC topology/address identity, and cloud-init. Replacement wipes the managed VM's disk. |
| Recovery guards | Failed-create marker, preservation/move-aside for unknown bundles, refusal to move a running unknown VM, and protection against forgetting a VM merely because an external disk is unmounted or read permission fails. |
| ISO implementation | Uses a host ISO tool where available and a built-in ISO9660 writer otherwise; cloud-init data is not dependent on VMware Tools being preinstalled. |

Multiple control planes do not currently provide a separately managed highly available API endpoint: both Ansible distros and the exported kubeconfig point at the first control plane. A VIP/load balancer and failure test are necessary before advertising automatic API failover.

The provider is small enough to audit directly: 35 Go `Test...` functions existed across its packages at the reviewed commit. Its host helpers bound `vmrun` execution, but `VdiskManager` uses an unbounded `exec.Command`; REST requests have a 30-second client timeout but do not take Terraform's request context.

Source: `providers/vmdesktop/internal/provider/{provider,host_data_source,network_resource,vm_resource}.go`, `providers/vmdesktop/internal/vmware/`, `cloudseed/localvm.py`, and `terraform/vmware/`.

## Ansible roles and security behavior

| Role | Implemented work |
|---|---|
| `common` | Base packages, UTC timezone, login message, and cloudseed PATH/symlinks for the login user. |
| `hardening` | sshd drop-ins/banner; PAM null-password removal; fail2ban; automatic host security updates; forwarding/kernel sysctls; core-dump restriction; sudo logging/PTY; umask; auditd; nftables; NAT preservation when the filtering firewall is disabled. |
| `tools` | Terraform and target cloud CLI on bastions; cluster-version-aware kubectl and GKE auth plugin; AWS FIPS endpoint environment setting. |
| `fips` | Ubuntu Pro attachment/fips-updates or Red Hat-family FIPS setup, reboot scheduling or inline reboot, kernel-state verification, and pending-marker lifecycle. |
| `k8s_common` | Swap disablement, overlay/br_netfilter, Kubernetes sysctls, node packages, apt file permissions, and hosts entries. |
| `rke2` | Version/channel bootstrap, existing-cluster version reuse, token/config, Canal, opt-in CIS profile and admission exemptions, ingress-controller disablement, serial control-plane startup/restart, and API wait. |
| `kubeadm` | containerd with systemd cgroups, Kubernetes repository and held packages, init/join and certificate transfer, pinned Flannel on initial installation, and kubeconfig. |
| `openvpn` | OpenVPN/Easy-RSA packages, EC PKI, CA/server certificate and CRL, server-certificate renewal, tls-crypt, server configuration, service, and client management helper. |
| `tailscale` | Installer, daemon, temporary auth-key file, and subnet-route advertisement. |
| `openscap` | OS-specific SCAP datastream or Ubuntu Security Guide selection, CIS/STIG profile selection, evaluation, report fetch, metadata, and explicit unsupported/not-applicable results. |

Host keys are checked using per-environment known-hosts information; first contact uses accept-new, and replacement identities permit a deliberate key refresh. `force_handlers=true` ensures failed provisioning still reloads services whose configuration changed. Bastion/VPN secrets are handed over separately and removed; Ubuntu Pro/Tailscale tokens use temporary 0600 files. The bootstrap restores enabled apt timers even on failure.

RKE2's default first installation follows the stable channel unless a version is supplied; joining nodes discover the existing server version. Its installation task uses `creates: /usr/local/bin/rke2`, so changing a variable is not an implemented rolling-upgrade workflow. kubeadm similarly holds installed packages and preserves the existing Flannel release. These are sound avoidance of accidental upgrades, but the missing deliberate upgrade lifecycle needs clear treatment.

Host hardening is not a claim that every CIS/STIG check passes. The scan role explicitly marks unavailable profiles or unsupported scanning combinations as not applicable. FIPS mode is an engineering configuration with separate scan checks; the README explicitly says it is not certification of the deployment. Preserve these distinctions in product copy.

Source: `ansible/ansible.cfg`, `ansible/{bootstrap.sh,bastion.yml,vpn.yml,kubernetes.yml,scan.yml}`, every role's `tasks/main.yml`, and `docs/guides/security-and-fips.md`.

## Findings requiring follow-up

### P1 — Fail closed when a VMware VM cannot be deleted

In the reviewed `providers/vmdesktop/internal/provider/vm_resource.go`, `Delete` ignores an `IsRunning` error, logs only a warning if the hard stop fails, logs only a warning if `deleteVM` fails, then calls `os.RemoveAll(state.vmDir())` and discards its error. Terraform can therefore consider deletion complete while files remain, or attempt filesystem deletion after failing to stop a VM. This is a source-confirmed error-handling gap, not a reproduced destructive operation.

Required outcome: refuse deletion when running state cannot be established; abort if a running VM cannot be stopped; check filesystem cleanup errors and retain state on failure. Test fake stop failure, status failure, permission-denied removal, absent bundles, and a successful retry.

**Remediation:** provider deletion now returns errors on status, stop, deleteVM, or filesystem failure. A successful stop is verified before files are removed, and failed-create cleanup follows the same rule. Cleanup uses the recorded VMX directory and refuses a renamed/additional running VM in that bundle. A partial deletion whose VMX is already gone stays in state through refresh so destroy can finish removing its remaining files. The Python leftover sweep also checks the running list, stop/delete results, and filesystem cleanup; failure aborts the CLI before it reports success or purges configuration. Fake-tool lifecycle tests cover each failure, an ineffective stop, missing storage, inaccessible files, and successful retries. These tests do not execute real VMware VMs.

### P1 — Record actual disk capacity after a failed initial expansion

In the same file, `Create` warns if `vmware-vdiskmanager -x` fails and continues with the base size, but keeps the requested `DiskGB` in Terraform state. `Read` refreshes CPU and memory from VMX, not disk capacity. A VM requested with a larger disk can therefore be recorded as already having that capacity, preventing a subsequent unchanged plan from retrying the expansion. `Update` already does better by retaining old disk size on grow failure.

Required outcome: determine actual VMDK capacity, record it honestly, and return an actionable error while preserving the created resource's identity. Add a failed-initial-grow test and a retry test.

**Provider remediation:** create, read, and disk updates now read the monolithic sparse VMDK header written by `vmware-vdiskmanager -t 0`, recording whole GiB without rounding upward. An initial grow failure records the VM identity and actual capacity, returns an error, and leaves the new VM stopped. A start failure also retains identity. Terraform taints a failed create; a later apply safely replaces it after the underlying error is fixed. Existing-VM expansion failures can retry in place. An unreadable disk during refresh warns and preserves the last known capacity so normal destroy/replacement can still clean it up. Tests exercise both retry paths, capacity drift, invalid headers, and failure to establish that a VM is stopped before hardware changes.

### P1 — Add live cloud lifecycle evidence

`tests/scenarios/lib.sh` states and implements that AWS/GCP/Azure scenarios remain dry-run even when `CLOUDSEED_LIVE=1`; that flag enables VMware only. Mocked Terraform tests and `terraform validate` check important schema and composition behavior, but cannot prove IAM permissions, quotas, marketplace terms, bootstrap sequencing, network reachability, Kubernetes readiness, VPN routing, or teardown in actual accounts.

Required outcome: isolated live cloud jobs for create, ready, access, add a platform item, mutate, restore, and destroy; short TTLs; explicit spend limits; cleanup evidence; and published results tied to the commit and runtime versions. Existing dry-run results should remain labeled as such.

### P2 — Introduce a runtime release manifest and complete provider locks

Only Azure/GCP stack and bootstrap lockfiles are tracked at the reviewed commit. `.gitignore` does not make exceptions for AWS's stack/bootstrap lockfiles. Image and bundle staging omit all provider lockfiles. Runtime defaults also mix pinned tool arguments, latest apt releases, a floating Terraform bundle version, broad Ansible requirements, and RKE2's stable channel.

Required outcome: one version manifest with tool, provider, host image, chart, and module provenance; generated locks for all registry-provider roots; an explicit decision about locks carried into bundles; and scheduled update PRs that run the compatibility checks. Keep the locally built VMware checksum exception separate.

### P2 — Finish the control-plane and node upgrade story

The local Ansible paths provision or join nodes but do not implement a staged RKE2/kubeadm upgrade with etcd snapshot, compatibility preflight, node drain, sequential control-plane upgrades, worker rollout, and rollback/failure guidance. The first control-plane address remains the connection/bootstrap endpoint. GKE instead auto-upgrades, while EKS/AKS behavior is governed by different cloud/provider settings.

Required outcome: an explicit compatibility matrix and target-specific upgrade plan rather than implying identical upgrade semantics. Add a stable local API endpoint if multiple-control-plane availability is a supported promise.

### P2 — Make durable state and shared-baseline ownership first-class

Existing flags cover important ownership cases, but multiple environments rely on operators choosing them correctly. GCP Data Access audit config can replace an existing `allServices` configuration; AWS account/regional controls and Azure Defender/terms are broader than the environment. Remote-state retention also differs by cloud.

Required outcome: discover existing ownership during setup; choose reuse/manage modes; show scope and retained resources in the plan; support a production retention preset; and exercise bootstrap recovery and destroy behavior in native tests. Add missing AWS/Azure bootstrap mocked suites.

### P2 — Narrow optional controller permissions and improve artifact verification

GCP external secrets gets project-wide secret access even before explicit per-secret scoping. The Docker AWS installer verifies a GPG signature, but the Debian-host AWS CLI task installs the HTTPS ZIP without equivalent verification. RKE2, Tailscale, and Azure host install scripts are fetched from moving HTTPS URLs; the SCAP release download lacks a checksum field. Checksums fetched from the same source are useful integrity checks, but they are not the same assurance as signed provenance.

Required outcome: explicit secret/resource scope inputs for optional controllers; a consistent download policy; pinned installer/content digests or signed release verification where supported; and a bill of materials for released artifacts. This is a consistency improvement, not evidence of a compromised download.

### P3 — Separate learning defaults from production availability options

Current defaults favor cost and simplicity: one AWS NAT, zonal GKE, AKS Free tier, a single bastion/VPN host, and a local API endpoint at control plane one. These are sensible lab defaults but should be visible in setup and architecture summaries.

Required outcome: documented lab/team/production presets with cost deltas and explicit availability changes. Regional GKE, appropriate AKS tier/zone controls, per-AZ NAT, and optional managed/private access are candidates, subject to live validation.

## Recommended additions in order

1. **Verified environment status:** one machine-readable report connecting resource state, last successful provisioning, live cluster access, node readiness, platform health, backup freshness, scan results, and version provenance. This would make the existing breadth understandable in the UI without adding another execution path.
2. **Release evidence and artifacts:** publish macOS/Linux bundles with checksums, SBOM/provenance, smoke tests, supported-tool versions, and live scenario evidence. This directly advances the existing 0.2 roadmap.
3. **Safe day-two lifecycle:** repair provider failure paths, add deliberate cluster upgrades, state export/recovery, and restoration acceptance criteria. Report incomplete actions clearly so reruns are actionable.
4. **Cloud baseline completeness:** implement the already-planned Azure VNet flow logs and optional GCP organization policies; add ownership/adoption checks so shared settings do not conflict across environments.
5. **Cost-aware reliability presets:** make topology, retention, private access, policy enforcement, and available capacity visible before apply, with monthly estimate differences and TTL-based lab teardown.
6. **Policy promotion:** formalize the roadmap's audit-to-enforce progression for Kyverno policies with a preview of workloads that would fail, an explicit exception model, and reversible rollout.
7. **Offline preparation:** if air-gapped operation is desired, build an explicit dependency/chart/image mirror export and import workflow. The present container and bundle are not an air-gap implementation.

Additional hypervisors and new clouds should follow this work; they would otherwise multiply lifecycle and compatibility combinations before the existing paths have comparable live evidence.

## Validation performed during this audit

| Check | Result |
|---|---|
| `bash -n` for the three `scripts/*.sh`, `ansible/bootstrap.sh`, and 17 scenario scripts | Passed for 21 scripts total. |
| `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./internal/vmware` | Passed; this package has 19 named test functions and does not need external modules. |
| `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go vet ./internal/vmware` | Passed. |
| The same offline `go test ./...` for the whole provider | Could not complete: Terraform plugin framework modules were not in the local cache and network module lookup was intentionally disabled. This was an environment/dependency limitation, not a failing provider assertion. |
| Terraform, Ansible, Docker/Podman execution | Not run in this audit; these executables were absent from PATH when checked. No dependency installers or provisioners were run. |
| Live cloud/VMware behavior | Not executed. Source-stated prior verification in README/roadmap was not independently re-created here. |

Repository-wide Python, documentation, and CI verification belongs to the accompanying review/change work. This report does not convert static coverage or prior documentation claims into a new live-deployment claim.
