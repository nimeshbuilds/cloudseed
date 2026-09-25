---
title: "Installation - cloudseed CLI, container image or single binary"
description: "Install cloudseed from source in one command, run it in a Docker or Podman container, or build a single binary with Terraform embedded."
---

# Installation

cloudseed is a Python command-line tool that uses only the standard library. You clone the repository and link the
launcher onto your `PATH`. Everything else (Terraform, cloud CLIs, kubectl, Helm) is installed when you first need it,
and only after you agree.

## Requirements

| | Requirement | Notes |
|---|---|---|
| Operating system | macOS or Linux | Native Windows environment-changing commands are unsupported: the environment lock requires POSIX file locking, and Ansible has no native Windows control node. Discovery and cached configuration remain available. |
| Python | **3.9 or newer** | The launcher checks the version and tells you how to upgrade. Nothing is `pip install`ed for the core CLI. |
| Terraform | **1.10 or newer** | Required for every target (S3 native state locking needs 1.10). cloudseed installs it for you: `cloudseed install terraform`. |
| OpenSSH | `ssh` and `ssh-keygen` | Preinstalled on macOS and most Linux distributions. |
| Cloud CLIs | optional | `aws`, `gcloud` and `az` are only a login convenience: Terraform's providers authenticate with your profiles, application-default credentials or environment variables. Azure's `az login` is the exception: it needs the `az` CLI unless you use `ARM_*` service-principal variables. |
| VMware (local target) | Fusion Pro 13+ or Workstation Pro 17+ | Both free. Go (1.24+) builds cloudseed's VMware provider once; qemu-img converts cloud images. `cloudseed install vmware` installs Terraform, Go, qemu-img and the provider. |

## Install

=== "From source (recommended)"

    ```bash
    git clone https://github.com/nimeshbuilds/cloudseed.git
    cloudseed/scripts/install.sh
    ```

    The script links `cloudseed` and the short alias `cs` into `/usr/local/bin` when it is writable, otherwise into
    `~/.local/bin`, and tells you if that directory is not on your `PATH`. The links point at your checkout, so a
    `git pull` updates cloudseed.

    | Option | What it does |
    |---|---|
    | `scripts/install.sh DIR` | link into `DIR` instead |
    | `--alias NAME` / `--no-alias` | pick another short name than `cs`, or none |
    | `--force` | move an existing `cloudseed` / alias that is not this checkout's aside (as `<name>.bak.<time>`) instead of stopping |
    | `--uninstall` | remove the links again (also `make uninstall`) |

    An existing `cloudseed` that is not yours stops the script with an explanation; an existing `cs` is left alone and
    the alias is skipped.

=== "Container (Docker or Podman)"

    Nothing to install on your machine except Docker or Podman. From a checkout:

    ```bash
    cloudseed deps image
    cloudseed --runtime container setup aws --env dev
    ```

    `deps image` builds `cloudseed:local` from the repository's `Dockerfile` with Terraform, the AWS CLI, gcloud, az,
    kubectl and Helm inside. `--runtime container` runs one command in it; `cloudseed deps runtime container` makes the
    container the default. `CLOUDSEED_HOME` is mounted at the same path, plus `~/.aws`, `~/.config/gcloud`, `~/.azure`
    and the cloud environment variables, so recorded paths and logins keep working.

=== "Single binary"

    For machines that have nothing on them. Build it once, on the same OS and CPU architecture as the target machine:

    ```bash
    cloudseed deps bundle
    ```

    The result, `dist/cloudseed-<os>-<arch>`, embeds the CLI, every Terraform module, the Ansible playbooks, the web
    console, the skills and a checksum-verified Terraform release. Copy it anywhere and run it. The build uses
    PyInstaller in a private virtualenv under `build/`.

Check the install:

```bash
cloudseed --version
cloudseed doctor
```

`doctor` lists the tools per target with versions, the container engines it found and whether it detected credentials
for each cloud. `cloudseed doctor aws` also checks the credentials live and ends with one verdict line when something
keeps that cloud from working.

## Install the tools you need

`cloudseed install` is the one front door for everything installable. It prefers Homebrew when it is present;
otherwise Terraform, kubectl, Helm, Go, k9s and the Databricks CLI come from their official releases, SHA-256 verified,
into `~/.cloudseed/bin` (no `sudo`).

```bash
cloudseed install list          # every target with its current status
cloudseed install terraform
cloudseed install cloud         # terraform + aws + gcloud + az
cloudseed install vmware        # terraform + go + qemu-img + cloudseed's VMware provider
cloudseed install kubernetes    # kubectl + helm
cloudseed install all           # all of the above, VPN clients and the agent skills
```

More on the three ways to satisfy dependencies (local tools, the container and the single binary) in
[Dependencies and runtimes](../guides/dependencies-and-runtimes.md).

## Log in to your cloud

cloudseed never asks for your cloud password. Log in the way you normally do; Terraform's providers pick it up.

=== "AWS"

    ```bash
    aws configure            # or: aws sso login --profile my-profile
    cloudseed doctor aws
    ```

    Pass `--profile NAME` to `setup` (or export `AWS_PROFILE`) to pick a profile.

=== "Google Cloud"

    ```bash
    gcloud auth application-default login
    cloudseed doctor gcp
    ```

    `setup gcp` needs a project: `--project-id` or `GOOGLE_PROJECT` / `GOOGLE_CLOUD_PROJECT`. A service-account key
    works too: `cloudseed creds set GOOGLE_APPLICATION_CREDENTIALS=/path/key.json`.

=== "Azure"

    ```bash
    az login
    cloudseed doctor azure
    ```

    `setup azure` needs a subscription: `--subscription-id`, `ARM_SUBSCRIPTION_ID`, or the one `az account show`
    reports. Service principals work through the `ARM_*` variables.

=== "VMware"

    Nothing to log in to. cloudseed configures VMware's REST service (`vmrest`) itself and keeps its generated
    credentials in `~/.cloudseed/vmware.json` (mode 0600).

To keep keys and tokens out of your shell profile, store them in cloudseed's local vault instead. Secrets are asked
with hidden input: `cloudseed creds set AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY`. See
[Credentials](../guides/credentials.md).

## Where cloudseed keeps things

Everything lives in `~/.cloudseed` (set `CLOUDSEED_HOME` to move it): environments under `envs/<cloud>-<env>/`, tools
under `bin/`, the VMware provider under `providers/`, logs, the undo journal and the credential vault. Outside it,
cloudseed only writes what you ask for: kubeconfig contexts (`cloudseed k8s kubeconfig`), agent skills
(`cloudseed skill install`), MCP client configs (`cloudseed mcp connect`) and the user services of the web console and
the MCP server (launchd on macOS, `systemd --user` on Linux).

## Update

```bash
git -C cloudseed pull
```

The links follow the checkout, so that is the whole update. Platform chart versions are pinned per cloudseed release:
after an update, `cs platform install <group> --upgrade` moves installed items to the new pins.

## Uninstall

1. Tear down what you created first: `cloudseed list` shows every environment, and
   `cloudseed destroy <cloud> --env <name>` removes one. Cloud resources are not removed by deleting files.
2. Stop the optional services if you turned them on: `cloudseed disable ui` and `cloudseed destroy mcp`.
3. Remove the links: `cloudseed/scripts/install.sh --uninstall`.
4. Delete `~/.cloudseed` and the checkout.
