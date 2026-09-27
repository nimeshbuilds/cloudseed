---
title: "Dependencies and runtimes - local tools, a container, or a single binary"
description: "Three ways to get cloudseed's tools: verified local installs, an all-in-one Docker or Podman image, or a single binary with Terraform embedded."
---

# Dependencies and runtimes

The cloudseed CLI itself needs only Python 3.9+. The tools it drives (Terraform above all, plus cloud CLIs, kubectl
and Helm when you use them) can come from three places, and you choose.

| Mode | How | When |
|---|---|---|
| **Install locally** | `cs install <tool>` or `cs deps install <tool>` | the default on a workstation |
| **Container** | `cs deps image`, then `cs --runtime container <command>` | nothing installed locally, or you want isolation |
| **Single binary** | `cs deps bundle` builds `dist/cloudseed-<os>-<arch>` | machines with nothing on them |

When a required tool is missing, `setup` asks which of the three you want. With `-y` it stops instead, with exit code
2 and the exact command to run, unless `CLOUDSEED_AUTO_INSTALL=1` approved installs up front.

```bash
cs deps status        # this machine: version, Python, runtime, container engines, and every tool per target
```

## What is required

| Tool | Needed for |
|---|---|
| Terraform **>= 1.10** | every target (S3 native state locking needs 1.10) |
| `ssh-keygen`, `ssh` | keys and the bastion |
| `aws`, `gcloud`, `az` | optional: login convenience and the cluster commands (fetching credentials). Azure's `az login` needs `az` unless you use `ARM_*` service-principal variables |
| kubectl, Helm | cluster commands and the platform catalog |
| Go 1.25+, qemu-img | VMware: building cloudseed's provider once, converting cloud images |
| VMware Fusion Pro 13+ / Workstation Pro 17+ | the VMware target |

cloudseed authenticates through Terraform's providers: environment variables, AWS profiles and SSO, Google application
default credentials and `az login`.

## 1. Install locally

```bash
cs install list                 # every installable target and whether it is present
cs install terraform
cs install cloud                # terraform aws gcloud az
cs install vmware               # terraform go qemu-img + the VMware provider
cs install kubernetes           # kubectl helm
cs install all                  # everything above, VPN clients and the agent skills
cs deps install terraform aws   # single tools only (its `all` is terraform aws gcloud az)
```

How tools are installed:

- **Homebrew** when it is available.
- Otherwise Terraform, kubectl, Helm, Go, k9s and the Databricks CLI come from their **official releases, SHA-256
  verified**, into `~/.cloudseed/bin`. No `sudo`.
- `aws` and `gcloud` from the vendors' installers over HTTPS; `az` and the Snowflake CLI with pip in their own
  virtualenv (Python 3.10+).
- qemu-img, OpenVPN and Tailscale from the OS package manager.
- kubescape and trivy when you name them, or when `cs scan` first needs them.

`cs install` is the one front door and also installs groups, [agent skills](agentic.md#skills-the-agents-operating-manuals),
agent CLIs and the VMware provider (`cs install vmware-provider --rebuild` rebuilds it). Installing is always yours:
inside an agent session cloudseed refuses it and hands you the command.

## 2. Run in a container

```bash
cs deps image                           # build cloudseed:local (asks Docker or Podman once)
cs deps image --engine podman --rebuild
cs --runtime container setup aws --env dev
cs deps runtime container               # make the container the default for every command
cs deps runtime auto                    # back to local tools, asking when something is missing
```

The image is built from the repository's `Dockerfile` with Terraform, the AWS CLI, gcloud, az, kubectl and Helm, on a
digest-pinned Python base image. When a command runs in it:

- `CLOUDSEED_HOME` is mounted at the **same path**, so every recorded path stays valid;
- `~/.aws`, `~/.config/gcloud` and `~/.azure` are mounted, and `AWS_*`, `GOOGLE_*` and `ARM_*` variables are passed;
- tools the container installs live in `~/.cloudseed/container-linux-<arch>/`, apart from your host's.

VMware environments always run on your machine (the hypervisor is local), whatever the runtime.

## 3. Build a single binary

```bash
cs deps bundle
```

`dist/cloudseed-<os>-<arch>` is one file with the CLI, every Terraform module, the Ansible playbooks, the web console,
the skills, the VMware provider sources and a checksum-verified Terraform release embedded. Build it on the same OS and
CPU architecture you will run it on; the build uses PyInstaller in a private virtualenv under `build/`. It is also
available as `cs install bundle` and `make bundle`.

## Cloudseed on the bastion

Normal provisioning installs `cloudseed` and its short alias `cs` for the SSH login user on AWS, GCP, Azure and
VMware bastions. The commands use the exact source payload copied from your current checkout, container or
standalone binary; provisioning does not download an unrelated latest Cloudseed release. A standalone binary
includes portable Python source for this purpose, so a macOS controller can provision a Linux bastion.

After setup, check the installation from your workstation:

```bash
cs ssh aws --env demo -- 'cs --version && cloudseed --version && cs help'
```

Replace `aws` and `demo` with your target and environment. Inside the bastion, `cs help` and `cs doctor` work
directly. The commands live in `~/.local/bin`; login and SSH shell startup include that directory and
`~/.cloudseed/bin`. An unrelated existing `cloudseed` or `cs` command in the installation location stops provisioning
with an explanation instead of being overwritten.

When Kubernetes and tools are enabled, the bastion also gets native `kubectl`, `helm` and `k9s`. Downloads use
published SHA-256 checksums; re-provisioning retains already installed Helm/k9s clients. `kubectl` follows the
configured cluster minor version when available, including the existing kubeadm default. VMware RKE2 with no configured
Kubernetes version uses the upstream stable client and reports that choice; check the running cluster version after
authenticating and keep the client [within one minor version of the API server](https://kubernetes.io/releases/version-skew-policy/#kubectl).

The bastion has its own local Cloudseed home. Installation does not copy the controller's environment records,
Terraform state, private SSH keys, kubeconfig or cloud credentials. Use an authorized bastion identity and kubeconfig
for cluster administration; keep infrastructure lifecycle commands on the original controller. Merely installing
the CLI does not grant cloud or cluster permissions.

`--no-tools` keeps the core Cloudseed CLI but skips extra cloud/Kubernetes clients. `--no-provision` skips this
installation, and `--sync-only` refreshes source files without repairing command links or installing clients.
To repair an older bastion from the current controller:

```bash
cs provision aws --env demo --host bastion
```

Provisioning checks both command names and the native cluster clients before reporting success. These checks verify
the installation; authenticating and reaching the private Kubernetes API remain separate checks.

## Related

- [Installation](../getting-started/installation.md)
- `cs help deps`, `cs help install`, `cs explain dependencies`
