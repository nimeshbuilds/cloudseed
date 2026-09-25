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

## Related

- [Installation](../getting-started/installation.md)
- `cs help deps`, `cs help install`, `cs explain dependencies`
