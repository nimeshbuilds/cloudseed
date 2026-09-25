---
title: "FAQ - cost, security, limits and supported versions"
description: "Honest answers about cloudseed: what it costs, how credentials are protected, what it does not do, and the supported Python, Terraform and VMware versions."
---

# FAQ

## The basics

??? question "What is cloudseed, in one sentence?"
    A command-line tool that builds secure landing zones (network, hardened bastion, logging, security baseline) on
    AWS, Google Cloud, Azure and local VMware with Terraform and Ansible, then adds a Kubernetes platform, backups,
    chaos engineering, compliance scans and cost reports on top, with a web console, an MCP server and optional AI
    agents that all run the same commands.

??? question "Is it free?"
    Yes. cloudseed is open source under the Apache-2.0 license. You pay your cloud provider for what it creates, and
    nothing else. The VMware target costs nothing beyond your own machine; VMware Fusion Pro and Workstation Pro are
    free.

??? question "Does it send telemetry or phone home?"
    No telemetry. The network calls it makes are the ones you would expect: your cloud's APIs (through Terraform and
    the cloud CLIs), downloads of tools, cloud images and Helm charts when you ask for them, and a public-IP lookup
    (`checkip.amazonaws.com` and fallbacks) so the bastion can be locked to your address. The web console loads nothing
    from a CDN.

??? question "How is this different from writing Terraform myself?"
    You could build all of it by hand, and cloudseed's Terraform is right there in `terraform/` to read. What you get
    on top: secure defaults decided for you, a plan and an approval before every change, per-environment working
    directories with non-overlapping networks, remote state bootstrapped and hardened, Ansible hardening after every
    apply, "already exists" handling that only adopts what is provably yours, targeted destroys, an undo journal, an
    audit trail, and a platform catalog with pinned versions. And the same shape on your laptop with VMware.

??? question "Can I use it without VMware or a cloud account?"
    Yes, to look around: `cloudseed setup aws --env demo --dry-run` renders and validates the complete Terraform with
    no credentials, and `cloudseed finops estimate aws --env demo` prices it. To build something real you need either
    VMware Fusion / Workstation or a cloud account.

## Cost

??? question "What does a landing zone cost to run?"
    cloudseed's own estimate for the defaults, at on-demand list prices, before data transfer:

    | Target | About | Mostly |
    |---|---|---|
    | AWS (us-east-1) | $58 / month | NAT gateway ($32.85), bastion, public IPv4, GuardDuty |
    | Azure (eastus) | $55 / month | NAT gateway ($32.85), bastion, public IPv4, Log Analytics |
    | Google Cloud (us-central1) | $11 / month | the e2-micro bastion and a static IP |
    | VMware | $0 | your machine |

    Managed Kubernetes, a VPN host, bigger nodes and platform items with cloud storage add to this. Run
    `cs finops estimate <cloud> --env <name>` for your configuration, and `cs finops cloud` for the actual bill. See
    [FinOps](../guides/finops.md).

??? question "How do I make sure I stop paying?"
    `cs destroy <cloud> --env <name>` removes everything the environment created; add `--purge-state` to remove the
    state bucket too. `cs list` shows every environment you have. A few account-wide AWS settings (the S3 public-access
    block, EBS encryption by default, the IAM password policy) stay in place after a destroy because they protect the
    whole account; they cost nothing.

## Security

??? question "Where do my cloud credentials go?"
    Nowhere new. cloudseed uses your existing logins through Terraform's providers, or the optional local vault
    (`~/.cloudseed/credentials.json`, mode 0600). Nothing in `~/.cloudseed` is copied to your hosts, no secret is stored
    in Terraform state or outputs, and logs are redacted. See [Credentials](../guides/credentials.md).

??? question "Is it safe to let an AI agent run it?"
    It is designed for it, with limits you should know. Agents never receive your credentials (they are stripped from
    the agent's environment and handed only to child cloudseed commands), every line of output is redacted, human-only
    commands are refused, and changes wait for your approval (the built-in agent) or for `confirm=true` (MCP). Claude
    Code runs with cloudseed's secret files denied. Codex, Gemini and Grok have no such file rules and could read files
    your user can read, so prefer the built-in agent or Claude Code for sensitive accounts. See
    [Agentic mode](../guides/agentic.md).

??? question "Who can reach the bastion?"
    Only the IPv4 addresses you allow (your detected public IP by default), with key-only SSH. `0.0.0.0/0`, ranges wider
    than a /8 and lists covering more than two /8s are refused. Workloads have no public address at all.

??? question "Are the web console and MCP server exposed to the network?"
    No. Both listen on 127.0.0.1 only, require a token, and check the `Host` and `Origin` headers. The MCP server also
    runs over stdio with no port at all. Do not put them behind a tunnel or public proxy.

## What it does not do

cloudseed is deliberately focused. Things it does **not** do today:

- **Multi-account organizations.** It manages one account, project or subscription per environment. It does not set up
  AWS Organizations, Control Tower, GCP folders or organization policies, or Azure management groups.
- **Deploy into an existing network.** It creates its own VPC or VNet. It adopts only resources whose tags prove they
  belong to the environment, never an arbitrary existing VPC.
- **Some logs and policies.** Azure NSG / VNet flow logs and GCP organization policies are not managed yet; GCP's
  default network is left untouched.
- **AWS China and isolated regions.** Not supported.
- **IPv6 allow-lists.** `--allow-ip` takes IPv4 only.
- **Spot or preemptible nodes.** Clusters use on-demand capacity; spot is a change you make outside cloudseed.
- **Upgrade local Kubernetes nodes.** On VMware, `kubernetes_version` pins what new nodes install and never upgrades a
  node that is already installed: upgrading a running RKE2 or kubeadm cluster is up to you.
- **Team collaboration.** Remote state gives locking, but an environment's configuration and SSH keys live in the
  working directory on the machine that created it. Sharing environments across people is not a built-in workflow.
- **Windows as a first-class host.** The VMware target on Windows is experimental (Ansible has no native Windows
  control node).
- **Public load balancers for apps.** Gateways get private load balancers; reach them over the VPN or the bastion.

## Supported versions

| Component | Supported |
|---|---|
| Python | **3.9 or newer** (standard library only) |
| Terraform | **1.10 or newer** (S3 native state locking) |
| Terraform providers | `hashicorp/aws` ~> 6, `hashicorp/google` 6.x and 7.x, `hashicorp/azurerm` >= 4.65 and < 5 |
| Host OS | macOS and Linux; Windows experimental for the VMware target |
| VMware | Fusion Pro 13+ (macOS, Intel and Apple silicon), Workstation Pro 17+ (Linux); older releases are refused for new environments |
| VMware guests | Ubuntu 24.04 (default), Ubuntu 22.04, Debian 12 (amd64 and arm64) |
| Cloud bastions | Amazon Linux 2023 (AWS), Debian 12 (GCP), Ubuntu 24.04 (Azure); Ubuntu Pro FIPS images in FIPS mode |
| Kubernetes | EKS, GKE, AKS; RKE2 (stable channel by default) or kubeadm (1.35 by default) on VMware |
| Helm | Helm 3 and Helm 4 |
| Go | 1.24+ (only to build the VMware provider) |

## Everything else

??? question "Can I change the Terraform?"
    Every stack variable is settable with `--var name=value` (`cs help variables <cloud>` lists them). For deeper
    changes, the stacks under `terraform/<cloud>/` are plain Terraform: fork them. The per-environment root cloudseed
    renders (`main.tf.json`) is regenerated on every run, so edit the inputs, not the rendered file.

??? question "What if I delete `~/.cloudseed`?"
    Don't, while environments exist. It holds each environment's configuration, SSH keys and (for local state and
    VMware) the Terraform state. Destroy your environments first (`cs list` shows them), then remove it.

??? question "How long does a setup take?"
    A VMware lab takes about ten minutes the first time (image download and provider build) and a couple of minutes
    after that. A cloud landing zone takes a few minutes; a managed Kubernetes cluster adds the time your provider
    needs to create it, often 10 to 20 minutes.

??? question "How are the docs and scenarios tested?"
    The [reference](../reference/index.md) is generated from the code by `scripts/gen-docs.py`. The VMware
    [scenarios](../scenarios/index.md) run live on VMware Fusion and the agent and console ones on a local machine; the
    AWS, Google Cloud and Azure scenarios are verified with `--dry-run` (Terraform render and validate) because the
    test machine has no cloud credentials.

??? question "Where do I report a bug or a security issue?"
    Bugs and ideas: [GitHub issues](https://github.com/nimeshbuilds/cloudseed/issues). Security issues: follow the
    [security policy](https://github.com/nimeshbuilds/cloudseed/blob/main/SECURITY.md) instead of opening a public
    issue.
