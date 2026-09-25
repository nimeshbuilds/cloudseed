---
name: cloudseed-vmware
description: Local virtual machines with the cloudseed CLI on VMware Fusion Pro (macOS) or Workstation Pro (Windows/Linux) - what `cloudseed setup vmware` builds, host/arch detection, guest OS choices, variables, outputs and gotchas. Use with the cloudseed skill when the user wants VMs on their own machine instead of a cloud.
---

# cloudseed on VMware Desktop (local)

`cloudseed setup vmware --env <env>` builds on the local machine:

- **Host detection**: Fusion Pro on macOS, Workstation Pro on Linux (and Windows, experimental: Ansible has no native
  Windows control node); host arch decides guest arch (Apple Silicon -> arm64 guests only, Intel/AMD -> amd64).
  Fusion Pro 13 / Workstation Pro 17 or newer: older releases are refused for new environments. A `VMWARE_HOME` that
  does not hold vmrun is reported by name. `cloudseed doctor vmware` shows what was found.
- **Private network**: by default VMware's built-in host-only vmnet (vmnet1 on Fusion) is adopted as it is: its
  existing subnet (e.g. `192.168.x.0/24`) and DHCP setting are kept - VMware serves DHCP on the upper half (e.g.
  `.128-.254`) - and the VMs use fixed addresses below the DHCP pool. Every environment without `--cidr` gets that same
  vmnet, so only one of them can have VMs: setup refuses a second one while another has VMs. To run two, give the new
  one its own network: `--cidr <cidr>` asks for a dedicated vmnet, created through vmrest with DHCP off; VMware only
  lets root create networks, so that needs `sudo vmrest` with `VMREST_USER`/`VMREST_PASSWORD` exported for it. An
  explicit `--cidr` must be a private (RFC 1918) range: a public one would hide the real hosts of that range from the
  host, and one containing 1.1.1.1 or 8.8.8.8 would also cut the VMs off from their DNS servers.
  When vmrest lists no host-only network, the placeholder - the first free `10.N.0.0/24` from `10.100.0.0/24` on,
  normally `10.100.0.0/24` itself - becomes this environment's own vmnet. Pass the network with `--cidr`, never
  `--var private_cidr`.
- **Address plan** (fixed offsets in the private network): bastion `.2`; workloads `.10+` (at most 10 when Kubernetes is
  on, they end at `.19`); control planes `.20-.39` (1-20); workers `.40-.99` (at most 60 on a /24): `.100-.127`, just
  below VMware's DHCP pool, are kept for MetalLB's LoadBalancer pool (platform catalog), so a LoadBalancer address never
  lands on a worker added later. Setup refuses counts that do not fit; an existing cluster that already has more
  workers is only warned (remove the ones above `wk60`, highest first, before using LoadBalancer services), and
  `cloudseed node add` refuses a node whose address would fall in the pool.
- **Pod / Service ranges**: with Kubernetes on, the private network must not overlap the cluster's pod or Service range
  (RKE2 `10.42.0.0/16` + `10.43.0.0/16`, kubeadm `10.244.0.0/16` + `10.96.0.0/16`). Setup refuses such a network for a
  new environment or when Kubernetes is turned on (pick another `--cidr`, or the other distro when it fits), and only
  warns for a cluster that already runs there.
- **Bastion VM**: NAT NIC (DHCP, reachable from the host) + private NIC (`.2`), forwards and NATs the private
  network; hardened by Ansible like cloud bastions (`nat_source_cidrs` keeps the NAT rules).
- **Workload VMs** (`workload_count`): private NIC only, static IPs `.10+`, default route via the bastion. They are
  bootstrapped by cloud-init only, not Ansible-hardened; VMs created by this version turn on unattended security
  updates themselves. Kubernetes nodes are hardened by the Kubernetes play and deliberately not auto-updated.
- **Images**: `guest_os` = ubuntu-24.04 (default) | ubuntu-22.04 | debian-12; downloaded + checksum-verified
  into `~/.cloudseed/images`, converted with qemu-img when only qcow2 is published (arm64 Ubuntu, Debian). Debian 12
  uses Debian's `generic` image: the `genericcloud` kernel has no AHCI driver for the cloud-init seed ISO.
- **Terraform**: cloudseed's own provider `registry.local/cloudseed/vmdesktop` (built from `providers/vmdesktop`
  with Go on first use). State is local, in the environment's working directory. Remote state, VPN and `update-ip` do
  not apply (the host reaches the VMs directly).
- **Kubernetes** (`enable_kubernetes=true`): control-plane (`.20+`) and worker (`.40+`) VMs on the private network,
  RKE2 (default) or kubeadm installed by Ansible from the host. RKE2's CIS hardening profile is not enabled unless
  `--var kubernetes_cis_profile=true` (RKE2 only, refused with kubeadm; it enforces the restricted Pod Security
  Standard outside the exempt namespaces - RKE2's system ones plus `cloudseed-scan`, `velero`, `local-path-storage`,
  `minio` and `chaos-mesh` -: pods that need root or host access are rejected unless their namespace is labelled
  `pod-security.kubernetes.io/enforce=privileged` or `baseline`). `cloudseed platform install` sets those labels itself
  before installing catalog items whose pods need more than restricted (privileged: velero, local-path-provisioner,
  metallb, kube-prometheus-stack, falco, neuvector, kured, chaos-mesh, istio ambient, kubescape-operator,
  trivy-operator; baseline: minio, loki, alloy and similar); `cloudseed platform info <item>` shows the level. The first control plane installs RKE2's stable channel
  (kubeadm: Kubernetes 1.35); nodes added later join at the version the cluster runs, and adding a control plane
  leaves the workers alone. `--var kubernetes_version` pins the release instead (RKE2 `v1.36.4+rke2r1`: every new node
  installs it, so changing it later puts new nodes on another version than the cluster; kubeadm `1.35`: only a new
  cluster uses it) and never upgrades a node that is already installed - it is not an upgrade path.
  `kubernetes_workers=0` puts the workloads on the control planes. Kubeconfig at `<workdir>/k8s/kubeconfig`;
  `cloudseed k8s kubeconfig vmware --env <env>` merges it into ~/.kube/config and makes it the current kubectl context
  (tell the user; `cloudseed undo` switches back); `cloudseed provision vmware --env <env> --host k8s` re-runs it.
- **FIPS** (`fips_mode=true`, new environments only): every VM attaches Ubuntu Pro (`export UBUNTU_PRO_TOKEN`, free for
  personal use) and enables fips-updates, `guest_os` must be Ubuntu, SSH keys are RSA-4096, and Kubernetes must be RKE2.

## Variables (`--var name=value`)

Complete list with defaults, generated from the Terraform: `cloudseed help variables vmware` (or `cloudseed help vmware-skill`).

- VMs: `guest_os` (ubuntu-24.04; a setup input, not a Terraform variable), `workload_count` (0), `ssh_username` (your local username,
  `--ssh-username`), `bastion_cpus` (2), `bastion_memory_mb` (2048), `bastion_disk_gb` (20), `workload_cpus` (2),
  `workload_memory_mb` (2048), `workload_disk_gb` (20), `packages` (extra packages on the bastion and workload VMs),
  `vm_dir` (default `<workdir>/vms`, i.e. `~/.cloudseed/envs/vmware-<env>/vms`; an absolute path, `~/...`, or a path
  relative to the working directory).
- Sizes can change later: CPUs and memory in place (the VM restarts); a larger `*_disk_gb` grows the disk in place, a
  smaller one rebuilds the VM (the plan shows a replace - point that out before approving). Changing `packages`
  rebuilds the bastion and the workload VMs; `ssh_username`, the SSH key, `guest_os`, `vm_dir` and `--name` rebuild
  every VM, Kubernetes nodes included (the plan says "must be replaced"). To add packages to running VMs, install
  them over `cloudseed ssh` instead.
- Size floors: vCPUs >= 1; memory >= 512 MB and a multiple of 4; disk >= 10 GB (Kubernetes nodes >= 20 GB); kubeadm
  needs 2 vCPUs and 2048 MB per node, RKE2 2048 MB (4096 recommended); no VM may have more vCPUs or memory than the
  host.
- Network: `private_cidr` - set it with `--cidr` (see Private network above).
- Kubernetes: `enable_kubernetes` (false), `kubernetes_distro` (rke2|kubeadm), `kubernetes_control_planes` (1),
  `kubernetes_workers` (2; 0 = the control planes run the workloads), `kubernetes_cpus` (2), `kubernetes_memory_mb`
  (4096), `kubernetes_disk_gb` (40), and two setup inputs (not Terraform variables): `kubernetes_version` ("" =
  automatic, nodes added later match the cluster; an RKE2 release such as `v1.36.4+rke2r1` or a kubeadm minor such as
  `1.35`, checked against the distro) and `kubernetes_cis_profile` (false; RKE2 only, refused with kubeadm).
- `fips_mode` (false).
- Set by cloudseed (refused in `--var`): `base_disk`, `guest_os_id` (from `guest_os`), `name`, `environment`,
  `ssh_public_key`. `tags` are not applied on VMware (VMs have no tags).

## Outputs

`host_product`, `host_version`, `guest_arch`, `private_vmnet`, `private_vmnet_adopted` (kept on destroy when true), `private_cidr`, `bastion_public_ip` (NAT address),
`bastion_private_ip`, `workload_private_ips`, `workload_names`, `ssh_user`, `kubernetes_distro`,
`kubernetes_control_plane_ips`, `kubernetes_worker_ips`, `kubernetes_endpoint`, `fips_mode`
(`cloudseed help outputs vmware` describes each).

## Gotchas

- If VMware is missing, `doctor vmware` prints the download link; nothing can be created without it.
- vmrest credentials are generated and configured by cloudseed automatically (no user action); VMREST_USER/VMREST_PASSWORD override them. When vmrest was never configured for this OS user, cloudseed configures it (its own credentials) - or, with the user's own VMREST_USER/VMREST_PASSWORD, says to run `vmrest -C` once.
- `vm_dir` is per environment by default (`<workdir>/vms`). Setup warns when the directory is shared with another
  environment or already holds other VMs, and refuses a new environment whose VM names (`<name>-<env>-*`) would clash
  with another's there; point that out to the user. A VM bundle named like one of the environment's VMs but unknown
  to its state is moved aside to `<name>.replaced-<time>.vmwarevm` (never deleted) when the VM is created; a running
  one stops the apply.
- `destroy` removes only this environment's VMs (`<name>-<env>-bastion|vmN|cpN|wkN`, or VMs Terraform recorded for it)
  and sweeps their files; other VMs in the same `vm_dir` are listed and never touched, and a `vm_dir` the user chose is
  never deleted. The built-in vmnet1 is always kept (and reused next time); a dedicated `--cidr` vmnet is removed from
  VMware's networking file with sudo when possible, otherwise it is kept and reused. With `--purge`, vmrest is stopped
  only when this cloudseed home started it, no other VMware environment is left and no VM is running.
- Workload VMs have no public address: reach them via `cloudseed ssh vmware --env <env>` then ssh to their private IP,
  or an SSH ProxyJump through the bastion.
- Never copy `~/.cloudseed` (keys/state) into a VM; only the repository is synced by `provision`.
