<p align="center">
  <a href="https://nimeshbuilds.github.io/cloudseed/">
    <img src="https://raw.githubusercontent.com/nimeshbuilds/cloudseed/main/assets/social-preview.png" alt="cloudseed: secure landing zones and a Kubernetes platform from one command, on AWS, GCP, Azure and VMware" width="820">
  </a>
</p>

<h3 align="center">Secure landing zones and a production Kubernetes platform on AWS, Google Cloud, Azure and your laptop, from one command.</h3>

<p align="center">
  <a href="https://github.com/nimeshbuilds/cloudseed/actions/workflows/tests.yml"><img src="https://github.com/nimeshbuilds/cloudseed/actions/workflows/tests.yml/badge.svg" alt="tests"></a>
  <a href="https://github.com/nimeshbuilds/cloudseed/actions/workflows/docs.yml"><img src="https://github.com/nimeshbuilds/cloudseed/actions/workflows/docs.yml/badge.svg" alt="docs"></a>
  <a href="https://github.com/nimeshbuilds/cloudseed/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-4f7df3" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-4f7df3?logo=python&amp;logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/terraform-%E2%89%A5%201.10-7c9cf8?logo=terraform&amp;logoColor=white" alt="Terraform 1.10+">
  <a href="https://github.com/nimeshbuilds/cloudseed/stargazers"><img src="https://img.shields.io/github/stars/nimeshbuilds/cloudseed?style=flat&amp;logo=github&amp;color=f59e0b" alt="GitHub stars"></a>
</p>

<p align="center">
  <a href="https://nimeshbuilds.github.io/cloudseed/getting-started/quickstart/"><b>Quick start</b></a> ·
  <a href="https://nimeshbuilds.github.io/cloudseed/scenarios/"><b>15 scenarios</b></a> ·
  <a href="https://nimeshbuilds.github.io/cloudseed/"><b>Docs</b></a> ·
  <a href="https://nimeshbuilds.github.io/cloudseed/guides/mcp/"><b>MCP server</b></a> ·
  <a href="https://github.com/nimeshbuilds/cloudseed/discussions"><b>Discussions</b></a>
</p>

---

Every cloud project starts with the same weeks of work: a VPC, private subnets, NAT, a bastion, audit logs and remote
state, then a Kubernetes cluster and a dozen add-ons. With cloudseed, **`cs setup` builds the landing zone and
`cs platform install` adds the platform**, on AWS, Google Cloud, Azure or VMware on your laptop, as plain Terraform
and Ansible that you own and can read.

- **Secure by default.** The bastion accepts SSH from your IP only. Workloads run in private subnets. Encryption, flow
  logs and the cloud's audit baseline are on from the start, and FIPS 140 mode is one flag.
- **Proven, not promised.** `cs dr test` backs up, deletes, restores and verifies a workload, then reports the restore
  time. Chaos suites and CIS / STIG scans end in PASS or FAIL.
- **Drive it your way.** Use the CLI, a local web console, an MCP server for Claude Code, Cursor, Codex or VS Code, or
  an AI agent that waits for your approval before it changes anything.

The CLI needs only Python 3.9+ and its standard library. No telemetry. Apache-2.0.

## 30-second demo

<p align="center">
  <img src="https://raw.githubusercontent.com/nimeshbuilds/cloudseed/main/docs/assets/demo.gif" alt="cloudseed demo: cs setup aws --dry-run renders and validates a secure AWS landing zone with private EKS, cs finops estimate prices it, and the local web console shows the same actions as buttons" width="900">
</p>

<sub>Recorded from this repository without cloud credentials: the AWS environment is a <code>--dry-run</code> (Terraform
rendered and validated, nothing created), the cost is <code>cs finops estimate</code>'s offline list-price estimate,
and the console is <code>cs enable ui</code> showing those environments.</sub>

## Quick start (3 commands)

```bash
git clone https://github.com/nimeshbuilds/cloudseed.git && cd cloudseed
./scripts/install.sh      # puts `cloudseed` and its alias `cs` on your PATH (no pip install)
cs setup aws --dry-run    # asks a few questions, validates the Terraform, creates nothing
```

Drop `--dry-run` to build it for real: cloudseed shows the Terraform plan and waits for your approval. Swap `aws` for
`gcp`, `azure`, or `vmware` (a local lab on VMware Fusion Pro / Workstation Pro, no cloud account needed). Missing
Terraform? `setup` offers to install it, or to run everything in a Docker/Podman image; `cs deps bundle` builds a
single binary.

```bash
cs doctor                                   # what's installed, how you're authenticated
cs setup gcp --var enable_kubernetes=true   # a GCP landing zone with a private GKE cluster
cs platform install basek8s                 # ArgoCD, Prometheus, Loki, Envoy, cert-manager
cs dr test                                  # back up, delete, restore, verify: PASS/FAIL
cs enable ui                                # the same thing as buttons, on 127.0.0.1
```

Full walkthrough: **[Quick start](https://nimeshbuilds.github.io/cloudseed/getting-started/quickstart/)** ·
[Installation](https://nimeshbuilds.github.io/cloudseed/getting-started/installation/) ·
[Concepts](https://nimeshbuilds.github.io/cloudseed/getting-started/concepts/) ·
[The manual (everything on one page)](https://nimeshbuilds.github.io/cloudseed/guides/manual/)

## Features

<table>
<tr>
<td width="33%" valign="top">

**Landing zones on three clouds**<br>
`cs setup aws|gcp|azure`: VPC/VNet, public + private subnets, NAT, flow logs, hardened bastion, CloudTrail / GuardDuty /
Access Analyzer, GCP audit logs, Azure Activity Log and optional Defender, encrypted remote state.

</td>
<td width="33%" valign="top">

**The same shape on your laptop**<br>
`cs setup vmware`: a NAT'd bastion and private VMs on VMware Fusion Pro or Workstation Pro, driven by cloudseed's own
Terraform provider. Add Kubernetes (RKE2 or kubeadm) with `--var enable_kubernetes=true`.

</td>
<td width="33%" valign="top">

**Private Kubernetes**<br>
EKS, GKE and AKS with private endpoints, workload identity and control-plane logging. `cs node add|remove|scale`,
`cs kubectl|helm|k9s` with an automatic tunnel through the bastion.

</td>
</tr>
<tr>
<td valign="top">

**Platform catalog: 73 items, 10 groups**<br>
`cs platform install <group>`: basek8s, scaling, data, ai, agentic, finops, devsecops, security, resilience, chaos.
Pinned charts, dependencies first, values per cloud and distro, cloud prerequisites created by Terraform.

</td>
<td valign="top">

**Backups you can prove**<br>
Velero with a bucket and least-privilege identity created for you. `cs dr test` backs up a sample workload (and a
volume's data), deletes it, restores it, verifies every object and reports PASS/FAIL with the restore time.

</td>
<td valign="top">

**Chaos engineering with verdicts**<br>
`cs chaos run basic|network|stress|full` with Chaos Mesh: pod kill, network delay/loss/partition, DNS errors, stress,
time skew, each with a steady-state hypothesis and a PASS / FAIL / INCONCLUSIVE report.

</td>
</tr>
<tr>
<td valign="top">

**Compliance scans**<br>
`cs scan <type>`: `cis` (kube-bench), `kube` (kubescape), `images` (trivy), `host` and `stig` (OpenSCAP CIS and DISA
STIG profiles), `cloud` (prowler) and `fips`, with saved reports.

</td>
<td valign="top">

**FIPS 140 mode**<br>
`--var fips_mode=true`: FIPS endpoints, FIPS node images, FIPS-only SSH and VPN algorithms, RSA-4096 keys, FIPS TLS on
the gateway, catalog items tiered by compatibility, and `cs scan fips` to verify it end to end.

</td>
<td valign="top">

**Private access**<br>
`--var enable_vpn=true`: an OpenVPN host with its own PKI (`cs vpn add-user`, `connect`, `revoke`) or a Tailscale
subnet router. `cs update-ip` when your IP changes.

</td>
</tr>
<tr>
<td valign="top">

**Local web console**<br>
`cs enable ui`: a token-protected console on 127.0.0.1 with a setup wizard, environment actions, the platform catalog,
DR, chaos, scans, reports and live output, and a "?" beside everything that explains it in place. Every button runs
the same `cloudseed` command.

</td>
<td valign="top">

**MCP server (30 tools)**<br>
`cs setup mcp` exposes every feature to Claude Code, Claude Desktop, Codex, Cursor, Windsurf, Gemini CLI and VS Code.
Anything destructive refuses to run without `confirm=true`.

</td>
<td valign="top">

**Agentic mode**<br>
`cs agentic "create a staging env on aws in us-west-2"` with the built-in agent, Claude Code, Codex, Gemini or Grok.
Credential variables are stripped from the agent, output is redacted, risky commands wait for you.

</td>
</tr>
<tr>
<td valign="top">

**FinOps**<br>
`cs finops estimate` prices an environment offline before you apply; `cs finops cloud` reads AWS Cost Explorer and
Azure Cost Management; `cs finops k8s` reads OpenCost allocation.

</td>
<td valign="top">

**Undo, audit, troubleshoot**<br>
`cs undo` reverts the last change (fifteen deep per environment, even a destroy). Every command lands in an audit
trail with redacted logs; `cs troubleshoot` recognises known failure signatures and prints the fix.

</td>
<td valign="top">

**Explains itself**<br>
`cs explain <feature>` shows which files, cloud resources and controls implement anything, and where its state lives.
`cs help` covers every command, topic, variable and output.

</td>
</tr>
</table>

## 15 step-by-step scenarios

Every scenario is a page you can follow command by command, and a script in
[`tests/scenarios/`](https://github.com/nimeshbuilds/cloudseed/tree/main/tests/scenarios) that runs exactly those
commands. VMware scenarios are verified live on VMware Fusion, the agent and console scenarios live on a local machine;
cloud scenarios are verified with `--dry-run` (Terraform rendered and validated, no account needed) and run for real
with your cloud credentials.

| # | Scenario | You end up with | Verified |
|---|---|---|---|
| 01 | [Your first lab on VMware](https://nimeshbuilds.github.io/cloudseed/scenarios/01-first-lab-vmware/) | a bastion and private VMs on your laptop: status, outputs, SSH, inventory, destroy | live |
| 02 | [AWS landing zone](https://nimeshbuilds.github.io/cloudseed/scenarios/02-aws-landing-zone/) | a secure AWS VPC with remote state, `update-ip` and a targeted destroy | dry-run |
| 03 | [GCP with private GKE](https://nimeshbuilds.github.io/cloudseed/scenarios/03-gcp-private-gke/) | a GCP landing zone, OS Login and a private GKE cluster | dry-run |
| 04 | [Azure with private AKS](https://nimeshbuilds.github.io/cloudseed/scenarios/04-azure-private-aks/) | an Azure landing zone, a private AKS cluster and Defender | dry-run |
| 05 | [Local Kubernetes](https://nimeshbuilds.github.io/cloudseed/scenarios/05-local-kubernetes/) | RKE2 (or kubeadm) on VMware with kubeconfig, `cs kubectl`, `helm`, `k9s` | live |
| 06 | [A platform in one command](https://nimeshbuilds.github.io/cloudseed/scenarios/06-platform-in-one-command/) | ArgoCD, observability, Gateway API + Envoy, cert-manager and secrets, UIs exposed | live |
| 07 | [Data and AI stack](https://nimeshbuilds.github.io/cloudseed/scenarios/07-data-and-ai-stack/) | MinIO, Postgres operator, Ollama + Open WebUI; install and uninstall single items | live |
| 08 | [Backups you can trust](https://nimeshbuilds.github.io/cloudseed/scenarios/08-backups-you-can-trust/) | Velero backups, schedules, restores and an automated `dr test` drill | live |
| 09 | [Chaos engineering](https://nimeshbuilds.github.io/cloudseed/scenarios/09-chaos-engineering/) | chaos suites with steady-state verdicts against your own Deployment, with reports | live |
| 10 | [Compliance scans](https://nimeshbuilds.github.io/cloudseed/scenarios/10-compliance-scans/) | CIS, kubescape, trivy, OpenSCAP CIS/STIG and FIPS reports | live |
| 11 | [FIPS 140 mode](https://nimeshbuilds.github.io/cloudseed/scenarios/11-fips-140-mode/) | a FIPS environment: what changes, what is refused, how it is verified | dry-run |
| 12 | [Private access with VPN](https://nimeshbuilds.github.io/cloudseed/scenarios/12-private-access-vpn/) | OpenVPN users, connect and revoke, or a Tailscale subnet router | dry-run |
| 13 | [Day-2 operations](https://nimeshbuilds.github.io/cloudseed/scenarios/13-day-2-operations/) | nodes added and removed, settings changed, `cs undo`, audit trail, troubleshooting, credentials vault | live |
| 14 | [AI agents and MCP](https://nimeshbuilds.github.io/cloudseed/scenarios/14-ai-agents-and-mcp/) | agentic mode, skills and redaction; the MCP server connected to your AI client | live (local) |
| 15 | [Web console and FinOps](https://nimeshbuilds.github.io/cloudseed/scenarios/15-web-console-and-finops/) | the console wizard, environment actions, explain panel, activity and cost estimates | live (local) |

**[Browse all scenarios and the feature coverage matrix](https://nimeshbuilds.github.io/cloudseed/scenarios/)**

## What you get on each target

| | AWS | GCP | Azure | VMware (local) |
|---|---|---|---|---|
| Network | VPC across 2+ AZs: public, private and isolated data subnets | custom VPC, public + private subnets, Private Google Access | VNet, public + private subnets, default outbound disabled | host-only private network behind a NAT'd bastion |
| Egress | NAT gateway (single or per AZ) | Cloud Router + Cloud NAT | NAT gateway | the bastion NATs the private network |
| Bastion | AL2023, IMDSv2, KMS-encrypted disk, SSM agent | Shielded VM, least-privilege service account | Ubuntu 24.04 Trusted Launch, managed identity | Ubuntu/Debian cloud image, cloud-init, SSH key only |
| SSH | from your IP only | from your IP only | from your IP only | from your machine |
| Logging | VPC flow logs to KMS-encrypted CloudWatch | subnet flow, NAT and firewall logs | Activity Log to Log Analytics | auditd + sudo log on the bastion |
| Baseline | CloudTrail, GuardDuty, Access Analyzer, EBS default encryption, optional Security Hub | required APIs, log retention, optional Data Access audit logs | optional Defender for Servers/Storage | the same Ansible hardening as the cloud bastions |
| State | S3: versioned, SSE-KMS, TLS-only, native locking | GCS: versioned, uniform access, public-access prevention | Storage account: TLS 1.2, versioning, soft delete | local |
| Kubernetes | private EKS | private GKE | private AKS | RKE2 or kubeadm |

The bastion (and the VPN host) is then hardened by Ansible: sshd hardening, fail2ban, unattended security updates,
sysctl, auditd and a default-deny nftables firewall. Details per cloud: `cs help aws|gcp|azure|vmware-skill`, the
[reference pages](https://nimeshbuilds.github.io/cloudseed/reference/) and
[the manual](https://nimeshbuilds.github.io/cloudseed/guides/manual/).

## Why cloudseed instead of hand-rolled Terraform?

You still get Terraform: every environment is a plain Terraform root (`main.tf.json` around the generic modules in
[`terraform/`](https://github.com/nimeshbuilds/cloudseed/tree/main/terraform)) you can read, plan and apply yourself.
cloudseed does the parts around it that usually take weeks and are easy to get wrong.

| | Hand-rolled Terraform | cloudseed |
|---|---|---|
| A secure network + bastion + baseline | pick modules, wire them, review every rule | `cs setup <cloud>`, plan shown before anything is created |
| SSH only from your IP | write the rule, fix it when your IP changes | the default; `cs update-ip` re-detects and re-applies |
| Remote state | bootstrap a bucket by hand first | `--state remote` creates a versioned, encrypted, TLS-only bucket first |
| Address space across environments | a spreadsheet | the first free `10.N.0.0/16`, never overlapping |
| Host hardening | a separate Ansible or cloud-init project | the bastion and VPN host are hardened by Ansible right after `setup` |
| Kubernetes add-ons | one Helm chart at a time, values per cloud | 73 pinned items, dependencies first, cloud identities and buckets created by Terraform |
| "Do our backups restore?" | a hope | `cs dr test`: PASS/FAIL with the measured restore time |
| Cost before apply | a separate tool or a guess | `cs finops estimate` |
| "Already exists" errors | manual `terraform import` | adopts only resources tagged as this environment's, refuses the rest |
| Rolling back a change | `git revert` and re-apply | `cs undo`, fifteen steps deep per environment |
| Tearing down EKS/GKE | orphaned load balancers and volumes | cloudseed deletes what Kubernetes created in the cloud first |
| Letting an AI agent help | hand it your shell and credentials | MCP tools with `confirm=true`, credentials stripped, output redacted |

## Security model

- **Network**: only the bastion (and the optional VPN host) has a public address. SSH is allowed from your IP only;
  `0.0.0.0/0`, anything wider than a /8, and lists covering more than two /8s are refused. Workloads and managed
  Kubernetes run in private subnets with private API endpoints by default.
- **Hosts**: key-only SSH, root login and passwords off, encrypted disks, IMDSv2 / Shielded VM / Trusted Launch, and
  Ansible hardening with a default-deny host firewall. SSH host keys are pinned per environment.
- **Secrets**: the stacks keep no secrets in state or outputs. Nothing from `~/.cloudseed` (state, keys) leaves your
  machine during provisioning, and every log and audit entry cloudseed writes is redacted.
- **Local services**: the web console (`127.0.0.1:7434`) and MCP server (`127.0.0.1:7433`) listen on loopback only,
  require a token (the MCP server unless you deploy it with `--no-auth`), check `Host` and `Origin`, and refuse
  framing. No CDN, no telemetry.
- **Agents**: credential variables are stripped from agent processes and handed only to child `cloudseed` commands
  over a per-session Unix socket; prompts and output are redacted line by line; commands that change your machine or
  cloudseed's settings are human-only; destructive MCP tools need `confirm=true`.
- **FIPS 140 mode** is an engineering control that `cs scan fips` verifies end to end, not a certification of your
  environment.

cloudseed is 0.x and has not had an independent security audit: review the plan it shows you and try it in a
non-production account first. Report vulnerabilities privately, see
[SECURITY.md](https://github.com/nimeshbuilds/cloudseed/blob/main/SECURITY.md).

## One tool, four ways to drive it

| Interface | Start with | Good for |
|---|---|---|
| CLI | `cs help` | scripts, CI, people who like terminals (`-y` never prompts) |
| Web console | `cs enable ui` | a guided wizard and one-click day-2 actions with live output |
| MCP server | `cs setup mcp` | asking Claude Code, Cursor, Codex, Gemini CLI or VS Code to plan, apply and troubleshoot |
| Agentic mode | `cs enable agentic` | `cs agentic "add two nodes to staging and run the CIS scan"` |

All four run the same deterministic `cloudseed` commands and write to the same audit trail.

## FAQ

<details>
<summary><b>What does it cost to try?</b></summary>

cloudseed itself is free and Apache-2.0. `--dry-run` creates nothing. Real cloud environments are billed by your
provider (a NAT gateway and a managed Kubernetes control plane are the usual big items); run
`cs finops estimate <cloud> --env <name>` before you apply, and `cs destroy` when you are done. The VMware target runs
on your own machine.
</details>

<details>
<summary><b>What do I need installed?</b></summary>

Python 3.9+ (standard library only) and Terraform 1.10+, which `cs setup` offers to install. For the cloud targets,
log in the usual way (`aws configure`, `gcloud auth application-default login`, `az login`). For the local target,
VMware Fusion Pro 13+ on macOS or Workstation Pro 17+ on Linux. Prefer not to install anything? Use
`--runtime container` (Docker or Podman) or `cs deps bundle` for a single binary.
</details>

<details>
<summary><b>Is it production ready?</b></summary>

It is a 0.1 release. The stacks follow each cloud's security guidance, are covered by about 3,400 unit tests and
mocked `terraform test` suites, and every change is shown as a Terraform plan first. It has not had an independent
security audit, and the cloud scenarios in the docs are verified with `--dry-run` in CI, so start in a
non-production account.
</details>

<details>
<summary><b>Can I customise what it builds?</b></summary>

Any stack variable can be set with `--var name=value` (`cs help variables <cloud>` lists them with defaults), tags
with `--tag`, and the address space with `--cidr`. Re-running `cs setup` shows a plan for the change. The generated
roots are plain Terraform, and outputs such as the private subnet IDs and the workload security group are there for
your own stacks.
</details>

<details>
<summary><b>Will an AI agent be able to destroy my infrastructure?</b></summary>

Not without you. Through MCP, anything that changes infrastructure is marked destructive and refuses to run without
`confirm=true`, so the client has to ask you. The built-in agent pauses for your approval on changes and previews
destroys first; credential and settings commands are refused in every agent session. Agentic mode is off until you
run `cs enable agentic`.
</details>

<details>
<summary><b>How is this different from AWS Control Tower or the Azure/GCP landing zone frameworks?</b></summary>

Those are single-cloud, organisation-level governance frameworks. cloudseed builds a secure environment (network,
bastion, baseline, state, Kubernetes and platform) per account, project or subscription, with the same commands on
three clouds and on your laptop. It can live inside an organisation those frameworks govern; turn off the baseline
parts they already manage with `--var` (for example `enable_account_baseline=false` or `enable_aws_config=false`).
</details>

<details>
<summary><b>Does it send telemetry?</b></summary>

No. There is no cloudseed server, account or telemetry. State lives in `~/.cloudseed` or in a bucket in your own
cloud account.
</details>

<details>
<summary><b>Where is the full reference?</b></summary>

On the [documentation site](https://nimeshbuilds.github.io/cloudseed/): the
[guides](https://nimeshbuilds.github.io/cloudseed/guides/cli/), the
[reference pages](https://nimeshbuilds.github.io/cloudseed/reference/) generated from the code (every command,
variable, output, catalog item and MCP tool), and [the manual](https://nimeshbuilds.github.io/cloudseed/guides/manual/),
every behaviour and known limit on one page. In the terminal: `cs help` and `cs explain`.
</details>

## Contributing

Bug reports, scenario requests, catalog items and code are welcome. Start with
[CONTRIBUTING.md](https://github.com/nimeshbuilds/cloudseed/blob/main/CONTRIBUTING.md) (dev setup, tests on Python
3.9, `make validate`, scenario scripts), check the [roadmap](https://github.com/nimeshbuilds/cloudseed/blob/main/ROADMAP.md),
and say hello in [Discussions](https://github.com/nimeshbuilds/cloudseed/discussions). Security issues go through
[private reporting](https://github.com/nimeshbuilds/cloudseed/security/advisories/new).

## License

[Apache-2.0](https://github.com/nimeshbuilds/cloudseed/blob/main/LICENSE). cloudseed is an independent open-source
project and is not affiliated with AWS, Google, Microsoft, Broadcom/VMware, HashiCorp or Anthropic. See
[NOTICE](https://github.com/nimeshbuilds/cloudseed/blob/main/NOTICE).

## Star history

<a href="https://star-history.com/#nimeshbuilds/cloudseed&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=nimeshbuilds/cloudseed&type=Date&theme=dark">
    <img alt="Star history of nimeshbuilds/cloudseed" src="https://api.star-history.com/svg?repos=nimeshbuilds/cloudseed&type=Date" width="600">
  </picture>
</a>

<p align="center"><sub>Built in public by <a href="https://github.com/nimeshbuilds">Nimesh Builds</a>, with AI. If cloudseed saved you a week of Terraform, a star helps others find it.</sub></p>
