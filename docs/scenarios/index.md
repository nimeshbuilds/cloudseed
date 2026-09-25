---
title: "Scenarios: 15 step-by-step cloudseed walkthroughs, tested"
description: "Fifteen tested, copy-paste walkthroughs covering every cloudseed feature: VMware labs, AWS, GCP and Azure landing zones, Kubernetes platforms, DR, AI agents."
---

# Scenarios

Fifteen walkthroughs, from a first lab on your laptop to a FIPS environment, a private GKE cluster, a DR drill and an
AI agent with an MCP server. Each page has numbered steps with exact commands, the output to expect, a
"verify it worked" check, a clean-up, and what just happened under the hood. Together they use **every command and
feature** of cloudseed ([coverage matrix](#command-coverage-matrix) below).

!!! tip "Every page is tested, and says how"
    - **Verified live on VMware Fusion 13.6**: the page's script builds real VMs and runs every command
      (`CLOUDSEED_LIVE=1 tests/scenarios/run.sh 05`).
    - **Verified with --dry-run**: cloud pages are rendered and checked with `terraform validate`, no account needed; the steps
      that need credentials are listed by the script and are yours to run.
    - **Verified live (local)**: the MCP server and the web console run for real in a throw-away home.
    - `tests/test_scenarios_docs.py` parses every command on these pages with cloudseed's own parser, so the docs
      cannot drift from the CLI.

## Pick a scenario

<div class="grid cards" markdown>

-   :material-laptop:{ .lg .middle } __01 · Your first lab on your laptop__

    ---

    A hardened bastion and a private network on VMware Fusion or Workstation: setup, status, SSH, inventory, destroy.

    <span style="white-space: nowrap">:material-signal-cellular-1: Beginner</span> · <span style="white-space: nowrap">:material-clock-outline: 15 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live</span>

    [:octicons-arrow-right-24: Start](01-first-lab-vmware.md)

-   :material-aws:{ .lg .middle } __02 · Secure AWS landing zone__

    ---

    Multi-AZ VPC, NAT, flow logs, bastion open only to your IP, CloudTrail + GuardDuty, S3 remote state, update-ip,
    targeted destroy.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 25 min</span> · <span style="white-space: nowrap">:material-cash: ≈ $58/mo</span> · <span style="white-space: nowrap">:material-test-tube: Dry-run</span>

    [:octicons-arrow-right-24: Start](02-aws-landing-zone.md)

-   :material-google-cloud:{ .lg .middle } __03 · GCP with a private GKE cluster__

    ---

    Custom VPC, Cloud NAT, OS Login bastion, private GKE with Workload Identity, SSH tunnel for kubectl, node scaling.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 30 min</span> · <span style="white-space: nowrap">:material-cash: ≈ $197/mo</span> · <span style="white-space: nowrap">:material-test-tube: Dry-run</span>

    [:octicons-arrow-right-24: Start](03-gcp-private-gke.md)

-   :material-microsoft-azure:{ .lg .middle } __04 · Azure with private AKS__

    ---

    VNet without default outbound, NSGs, NAT gateway, Defender, private AKS, node pool resizing, prowler CIS scan.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 30 min</span> · <span style="white-space: nowrap">:material-cash: ≈ $150/mo</span> · <span style="white-space: nowrap">:material-test-tube: Dry-run</span>

    [:octicons-arrow-right-24: Start](04-azure-private-aks.md)

-   :material-kubernetes:{ .lg .middle } __05 · Kubernetes on your laptop__

    ---

    RKE2 (or kubeadm) on private VMs, kubeconfig, `cs kubectl` / `helm` / `k9s`, the current environment, a first app.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 35 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live</span>

    [:octicons-arrow-right-24: Start](05-local-kubernetes.md)

-   :material-rocket-launch-outline:{ .lg .middle } __06 · A production platform in one command__

    ---

    ArgoCD, Prometheus + Grafana, Loki, OpenTelemetry, Gateway API + Envoy, cert-manager, secrets; UIs over TLS; a CI
    template.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 30 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live</span>

    [:octicons-arrow-right-24: Start](06-platform-in-one-command.md)

-   :material-database-outline:{ .lg .middle } __07 · Data and AI stack__

    ---

    MinIO, a CloudNativePG Postgres, a dev Kafka, Ollama + Open WebUI, remembered `--set` values, Databricks and
    Snowflake profiles.

    <span style="white-space: nowrap">:material-signal-cellular-3: Advanced</span> · <span style="white-space: nowrap">:material-clock-outline: 40 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live</span>

    [:octicons-arrow-right-24: Start](07-data-and-ai-stack.md)

-   :material-backup-restore:{ .lg .middle } __08 · Backups you can trust__

    ---

    Velero with its bucket and identity created for you: back up, break, restore, schedule, and an automated DR drill.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 20 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live</span>

    [:octicons-arrow-right-24: Start](08-backups-you-can-trust.md)

-   :material-lightning-bolt-outline:{ .lg .middle } __09 · Chaos engineering with verdicts__

    ---

    Chaos Mesh experiments with steady-state hypotheses, against a canary and your own Deployment; PASS / FAIL
    reports.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 20 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live</span>

    [:octicons-arrow-right-24: Start](09-chaos-engineering.md)

-   :material-shield-check-outline:{ .lg .middle } __10 · Compliance scans__

    ---

    CIS with kube-bench, NSA / MITRE with kubescape, image CVEs with trivy, OpenSCAP CIS and STIG on hosts, reports.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 25 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live</span>

    [:octicons-arrow-right-24: Start](10-compliance-scans.md)

-   :material-shield-lock-outline:{ .lg .middle } __11 · FIPS 140 mode__

    ---

    What one switch changes, what it refuses, the platform's FIPS tiers, and end-to-end verification with
    `cs scan fips`.

    <span style="white-space: nowrap">:material-signal-cellular-3: Advanced</span> · <span style="white-space: nowrap">:material-clock-outline: 15-45 min</span> · <span style="white-space: nowrap">:material-cash: $0 offline</span> · <span style="white-space: nowrap">:material-test-tube: Dry-run</span>

    [:octicons-arrow-right-24: Start](11-fips-140-mode.md)

-   :material-vpn:{ .lg .middle } __12 · Private access with a VPN__

    ---

    A hardened OpenVPN host with its own PKI (users, profiles, connect, revoke) or a Tailscale subnet router.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 20 min</span> · <span style="white-space: nowrap">:material-cash: ≈ $70/mo</span> · <span style="white-space: nowrap">:material-test-tube: Dry-run</span>

    [:octicons-arrow-right-24: Start](12-private-access-vpn.md)

-   :material-wrench-outline:{ .lg .middle } __13 · Day-2 operations__

    ---

    Add and remove nodes, change settings and undo them, inventory and audit trail, troubleshooting, the credential
    vault.

    <span style="white-space: nowrap">:material-signal-cellular-2: Intermediate</span> · <span style="white-space: nowrap">:material-clock-outline: 30 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live</span>

    [:octicons-arrow-right-24: Start](13-day-2-operations.md)

-   :material-robot-outline:{ .lg .middle } __14 · AI agents and MCP__

    ---

    Agentic mode with Claude Code, Codex, Gemini or the built-in agent; skills; redaction; an MCP server for your
    AI clients.

    <span style="white-space: nowrap">:material-signal-cellular-1: Beginner</span> · <span style="white-space: nowrap">:material-clock-outline: 15 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live (local)</span>

    [:octicons-arrow-right-24: Start](14-ai-agents-and-mcp.md)

-   :material-monitor-dashboard:{ .lg .middle } __15 · Web console and FinOps__

    ---

    The local console (wizard, actions, Activity, explain), then estimates, the cloud bill, OpenCost and a report
    for an agent.

    <span style="white-space: nowrap">:material-signal-cellular-1: Beginner</span> · <span style="white-space: nowrap">:material-clock-outline: 15 min</span> · <span style="white-space: nowrap">:material-cash: $0</span> · <span style="white-space: nowrap">:material-check-decagram: Live (local)</span>

    [:octicons-arrow-right-24: Start](15-web-console-and-finops.md)

</div>

## Suggested paths

| If you ... | Follow |
|---|---|
| have no cloud account (everything local, $0) | [01](01-first-lab-vmware.md) → [05](05-local-kubernetes.md) → [06](06-platform-in-one-command.md) → [08](08-backups-you-can-trust.md) → [09](09-chaos-engineering.md) → [10](10-compliance-scans.md) → [13](13-day-2-operations.md) |
| run infrastructure on a cloud | [02](02-aws-landing-zone.md) or [03](03-gcp-private-gke.md) or [04](04-azure-private-aks.md) → [12](12-private-access-vpn.md) → [06](06-platform-in-one-command.md) → [08](08-backups-you-can-trust.md) → [15](15-web-console-and-finops.md) |
| work in a regulated environment | [11](11-fips-140-mode.md) → [10](10-compliance-scans.md) → [02](02-aws-landing-zone.md) → [13](13-day-2-operations.md) |
| want an AI agent to do it | [14](14-ai-agents-and-mcp.md) → [15](15-web-console-and-finops.md) → [01](01-first-lab-vmware.md) |

## Every feature, and where to try it

| Feature | What you do with it | Scenarios |
|---|---|---|
| Landing zones on AWS, GCP, Azure | VPC / VNet, public, private and data subnets, NAT, flow logs, hardened bastion, security baseline, remote state | [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) |
| Local VMware environments | The same shape on Fusion Pro / Workstation Pro through cloudseed's own Terraform provider | [01](01-first-lab-vmware.md) · [05](05-local-kubernetes.md) |
| Managed and local Kubernetes | Private EKS / GKE / AKS, RKE2 or kubeadm on VMs, kubeconfig, tunnels, `cs kubectl` / `helm` / `k9s` | [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) |
| Node pools | `cs node add / remove / scale` through the cloud API or Terraform + Ansible | [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [13](13-day-2-operations.md) |
| Platform catalog | Ten groups of pinned Helm / kustomize items: plan, install, uninstall, `--set`, `--upgrade`, UIs over TLS | [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) · [08](08-backups-you-can-trust.md) · [09](09-chaos-engineering.md) |
| Platform template gitlab-ci | A CI pipeline (build, test, trivy scan, release, ArgoCD deploy) for your app repository | [06](06-platform-in-one-command.md) |
| Managed data services | Databricks and Snowflake connection profiles per environment, vendor CLIs passed through | [07](07-data-and-ai-stack.md) |
| Disaster recovery (Velero) | Bucket + identity created for you, backup, restore, schedules, the automated `cs dr test` drill | [08](08-backups-you-can-trust.md) |
| Chaos engineering | Chaos Mesh experiments with steady-state verdicts and saved reports | [09](09-chaos-engineering.md) |
| Compliance and vulnerability scans | kube-bench CIS, kubescape NSA / MITRE, trivy, OpenSCAP CIS / STIG, prowler cloud CIS, reports | [10](10-compliance-scans.md) · [04](04-azure-private-aks.md) |
| FIPS 140 mode | FIPS endpoints, images, kernels, keys and ciphers; refusals; `cs scan fips` | [11](11-fips-140-mode.md) · [10](10-compliance-scans.md) |
| VPN | OpenVPN with its own PKI, or a Tailscale subnet router | [12](12-private-access-vpn.md) |
| Undo | `cs undo`: fifteen undo points per environment (at most five of one kind), `--global`, `--id`, `--drop`, from CLI, console, agents and MCP | [13](13-day-2-operations.md) · [06](06-platform-in-one-command.md) · [08](08-backups-you-can-trust.md) · [14](14-ai-agents-and-mcp.md) |
| Audit trail, inventory, troubleshooting | `logs/audit.jsonl`, full redacted logs, `inventory.json`, deterministic `cs troubleshoot` | [13](13-day-2-operations.md) · [01](01-first-lab-vmware.md) · [15](15-web-console-and-finops.md) |
| Credential vault | `cs creds`: hidden input, 0600 file, injected everywhere, stripped from agents | [13](13-day-2-operations.md) · [02](02-aws-landing-zone.md) · [14](14-ai-agents-and-mcp.md) |
| Dependencies, container runtime, single binary | `cs deps install`, `cs deps image` + `--runtime container`, `cs deps bundle`, `cs install ...` | [02](02-aws-landing-zone.md) · [05](05-local-kubernetes.md) · [10](10-compliance-scans.md) |
| Help system and `cs explain` | Per-command help, topics, generated variable and output references, how anything is implemented | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [15](15-web-console-and-finops.md) |
| FinOps | Estimates before you apply, the provider bill, OpenCost allocation, one report for an agent | [15](15-web-console-and-finops.md) · [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) |
| Web console | `cs enable ui`: the wizard, environment actions, platform, resilience, reports, explain panel, Activity | [15](15-web-console-and-finops.md) |
| AI agents | Agentic mode (built-in, Claude Code, Codex, Gemini, Grok), headliner brief, skills, redaction, approvals | [14](14-ai-agents-and-mcp.md) |
| MCP server | Every feature as a tool for Claude Code, Claude Desktop, Cursor, VS Code, Codex, Gemini CLI, Windsurf | [14](14-ai-agents-and-mcp.md) |
| Access and hardening | `cs ssh`, `cs update-ip`, `cs provision` (Ansible hardening, re-runnable) | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [12](12-private-access-vpn.md) · [13](13-day-2-operations.md) |

## Run the scenarios yourself

The scripts live next to the code in [`tests/scenarios/`](https://github.com/nimeshbuilds/cloudseed/tree/main/tests/scenarios).
They never touch your `~/.cloudseed` unless you ask for a live run:

```bash
tests/scenarios/run.sh                      # all 15: cloud ones as dry runs, VMware ones as their dry-run equivalent
tests/scenarios/run.sh 02 14                # just these
tests/scenarios/run.sh -v 03                # stream every command's output
CLOUDSEED_LIVE=1 tests/scenarios/run.sh 01 05 06 08
python3 -m unittest tests.test_scenarios_docs
```

`run.sh` prints a table (scenario, mode, result, checks, skipped live steps, time). A live run builds real VMs with
VMware Fusion Pro / Workstation Pro; the cluster scenarios share the `vmware-lab` cluster from 05 and destroy it at the
end.

## Command coverage matrix

Every command and sub-command of the CLI, and the scenarios whose steps run it. The tables are generated
from the pages and checked by `tests/test_scenarios_docs.py`, so they are always current and nothing is left out.

<!-- coverage-matrix:start (generated: python3 tests/test_scenarios_docs.py --write-matrix) -->

### Environments

| Command | Scenarios that run it |
|---|---|
| `cs setup aws` | [02](02-aws-landing-zone.md) · [11](11-fips-140-mode.md) · [12](12-private-access-vpn.md) · [15](15-web-console-and-finops.md) |
| `cs setup gcp` | [03](03-gcp-private-gke.md) · [11](11-fips-140-mode.md) · [12](12-private-access-vpn.md) |
| `cs setup azure` | [04](04-azure-private-aks.md) |
| `cs setup vmware` | [01](01-first-lab-vmware.md) · [05](05-local-kubernetes.md) · [11](11-fips-140-mode.md) · [13](13-day-2-operations.md) |
| `cs plan` | [02](02-aws-landing-zone.md) · [13](13-day-2-operations.md) |
| `cs apply` | [02](02-aws-landing-zone.md) · [13](13-day-2-operations.md) |
| `cs status` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [13](13-day-2-operations.md) |
| `cs output` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [12](12-private-access-vpn.md) |
| `cs list` | [01](01-first-lab-vmware.md) · [13](13-day-2-operations.md) |
| `cs inventory` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [13](13-day-2-operations.md) |
| `cs troubleshoot` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [05](05-local-kubernetes.md) · [12](12-private-access-vpn.md) · [13](13-day-2-operations.md) |
| `cs doctor` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) · [13](13-day-2-operations.md) |
| `cs update-ip` | [02](02-aws-landing-zone.md) · [13](13-day-2-operations.md) |
| `cs provision` | [12](12-private-access-vpn.md) · [13](13-day-2-operations.md) |
| `cs destroy` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) · [11](11-fips-140-mode.md) · [12](12-private-access-vpn.md) · [15](15-web-console-and-finops.md) |

### Access

| Command | Scenarios that run it |
|---|---|
| `cs ssh` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [11](11-fips-140-mode.md) |
| `cs vpn status` | [12](12-private-access-vpn.md) |
| `cs vpn add-user` | [12](12-private-access-vpn.md) |
| `cs vpn revoke` | [12](12-private-access-vpn.md) |
| `cs vpn users` | [12](12-private-access-vpn.md) |
| `cs vpn connect` | [12](12-private-access-vpn.md) |
| `cs vpn disconnect` | [12](12-private-access-vpn.md) |
| `cs vpn provision` | [12](12-private-access-vpn.md) |

### Kubernetes

| Command | Scenarios that run it |
|---|---|
| `cs k8s info` | [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) |
| `cs k8s kubeconfig` | [03](03-gcp-private-gke.md) · [05](05-local-kubernetes.md) |
| `cs k8s tunnel` | [03](03-gcp-private-gke.md) |
| `cs k8s untunnel` | [03](03-gcp-private-gke.md) |
| `cs env show` | [05](05-local-kubernetes.md) |
| `cs env use` | [05](05-local-kubernetes.md) |
| `cs env clear` | [05](05-local-kubernetes.md) |
| `cs node add` | [04](04-azure-private-aks.md) · [13](13-day-2-operations.md) |
| `cs node list` | [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) · [13](13-day-2-operations.md) |
| `cs node remove` | [04](04-azure-private-aks.md) · [13](13-day-2-operations.md) |
| `cs node scale` | [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [13](13-day-2-operations.md) |
| `cs kubectl` | [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) · [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) · [08](08-backups-you-can-trust.md) |
| `cs helm` | [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) · [06](06-platform-in-one-command.md) |
| `cs k9s` | [05](05-local-kubernetes.md) |

### Platform catalog

| Command | Scenarios that run it |
|---|---|
| `cs platform list` | [06](06-platform-in-one-command.md) |
| `cs platform info` | [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) · [08](08-backups-you-can-trust.md) |
| `cs platform plan` | [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) · [08](08-backups-you-can-trust.md) · [09](09-chaos-engineering.md) · [11](11-fips-140-mode.md) |
| `cs platform install` | [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) · [08](08-backups-you-can-trust.md) · [15](15-web-console-and-finops.md) |
| `cs platform uninstall` | [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) · [08](08-backups-you-can-trust.md) · [09](09-chaos-engineering.md) |
| `cs platform status` | [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) |
| `cs platform ui` | [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) |
| `cs platform template` | [06](06-platform-in-one-command.md) |

### Resilience and security

| Command | Scenarios that run it |
|---|---|
| `cs dr status` | [08](08-backups-you-can-trust.md) |
| `cs dr backup` | [08](08-backups-you-can-trust.md) |
| `cs dr restore` | [08](08-backups-you-can-trust.md) |
| `cs dr backups` | [08](08-backups-you-can-trust.md) |
| `cs dr schedule` | [08](08-backups-you-can-trust.md) |
| `cs dr test` | [08](08-backups-you-can-trust.md) |
| `cs dr describe` | [08](08-backups-you-can-trust.md) |
| `cs dr logs` | [08](08-backups-you-can-trust.md) |
| `cs chaos run` | [09](09-chaos-engineering.md) |
| `cs chaos list` | [09](09-chaos-engineering.md) |
| `cs chaos status` | [09](09-chaos-engineering.md) |
| `cs chaos stop` | [09](09-chaos-engineering.md) |
| `cs chaos report` | [09](09-chaos-engineering.md) |
| `cs scan cis` | [10](10-compliance-scans.md) |
| `cs scan kube` | [10](10-compliance-scans.md) |
| `cs scan images` | [10](10-compliance-scans.md) |
| `cs scan host` | [10](10-compliance-scans.md) |
| `cs scan stig` | [10](10-compliance-scans.md) |
| `cs scan cloud` | [04](04-azure-private-aks.md) · [10](10-compliance-scans.md) |
| `cs scan fips` | [10](10-compliance-scans.md) · [11](11-fips-140-mode.md) |
| `cs scan all` | [10](10-compliance-scans.md) |
| `cs scan reports` | [10](10-compliance-scans.md) · [11](11-fips-140-mode.md) |

### Cost and data

| Command | Scenarios that run it |
|---|---|
| `cs finops estimate` | [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [12](12-private-access-vpn.md) · [15](15-web-console-and-finops.md) |
| `cs finops cloud` | [15](15-web-console-and-finops.md) |
| `cs finops k8s` | [15](15-web-console-and-finops.md) |
| `cs finops report` | [15](15-web-console-and-finops.md) |
| `cs databricks connect` | [07](07-data-and-ai-stack.md) |
| `cs databricks test` | [07](07-data-and-ai-stack.md) |
| `cs databricks status` | [07](07-data-and-ai-stack.md) |
| `cs databricks <cli args>` | [07](07-data-and-ai-stack.md) |
| `cs snowflake connect` | [07](07-data-and-ai-stack.md) |
| `cs snowflake test` | [07](07-data-and-ai-stack.md) |
| `cs snowflake status` | [07](07-data-and-ai-stack.md) |
| `cs snowflake <cli args>` | [07](07-data-and-ai-stack.md) |

### AI agents and MCP

| Command | Scenarios that run it |
|---|---|
| `cs enable agentic` | [14](14-ai-agents-and-mcp.md) |
| `cs enable headliner` | [14](14-ai-agents-and-mcp.md) |
| `cs enable mcp` | [14](14-ai-agents-and-mcp.md) |
| `cs enable ui` | [15](15-web-console-and-finops.md) |
| `cs disable agentic` | [14](14-ai-agents-and-mcp.md) |
| `cs disable headliner` | [14](14-ai-agents-and-mcp.md) |
| `cs disable mcp` | [14](14-ai-agents-and-mcp.md) |
| `cs disable ui` | [15](15-web-console-and-finops.md) |
| `cs agents` | [14](14-ai-agents-and-mcp.md) |
| `cs use` | [14](14-ai-agents-and-mcp.md) |
| `cs model` | [14](14-ai-agents-and-mcp.md) |
| `cs agentic` | [14](14-ai-agents-and-mcp.md) · [15](15-web-console-and-finops.md) |
| `cs do` | [14](14-ai-agents-and-mcp.md) |
| `cs skill list` | [14](14-ai-agents-and-mcp.md) |
| `cs skill install` | [14](14-ai-agents-and-mcp.md) |
| `cs skill show` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp setup` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp status` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp guide` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp connect` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp disconnect` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp tools` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp config` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp test` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp serve` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp start` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp stop` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp restart` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp logs` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp token` | [14](14-ai-agents-and-mcp.md) |
| `cs mcp uninstall` | [14](14-ai-agents-and-mcp.md) |

### Console, safety and help

| Command | Scenarios that run it |
|---|---|
| `cs ui open` | [15](15-web-console-and-finops.md) |
| `cs ui start` | [15](15-web-console-and-finops.md) |
| `cs ui status` | [15](15-web-console-and-finops.md) |
| `cs ui stop` | [15](15-web-console-and-finops.md) |
| `cs ui restart` | [15](15-web-console-and-finops.md) |
| `cs ui logs` | [15](15-web-console-and-finops.md) |
| `cs ui token` | [15](15-web-console-and-finops.md) |
| `cs ui serve` | [15](15-web-console-and-finops.md) |
| `cs undo` | [06](06-platform-in-one-command.md) · [08](08-backups-you-can-trust.md) · [13](13-day-2-operations.md) |
| `cs undo --list` | [13](13-day-2-operations.md) · [14](14-ai-agents-and-mcp.md) |
| `cs undo --global` | [13](13-day-2-operations.md) |
| `cs undo --id` | [13](13-day-2-operations.md) |
| `cs undo --drop` | [13](13-day-2-operations.md) |
| `cs creds list` | [13](13-day-2-operations.md) |
| `cs creds set` | [02](02-aws-landing-zone.md) · [11](11-fips-140-mode.md) · [12](12-private-access-vpn.md) · [13](13-day-2-operations.md) · [14](14-ai-agents-and-mcp.md) |
| `cs creds unset` | [11](11-fips-140-mode.md) · [13](13-day-2-operations.md) |
| `cs creds clear` | [13](13-day-2-operations.md) |
| `cs explain` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) · [06](06-platform-in-one-command.md) · [07](07-data-and-ai-stack.md) · [08](08-backups-you-can-trust.md) · [09](09-chaos-engineering.md) · [10](10-compliance-scans.md) · [11](11-fips-140-mode.md) · [12](12-private-access-vpn.md) · [13](13-day-2-operations.md) · [14](14-ai-agents-and-mcp.md) · [15](15-web-console-and-finops.md) |
| `cs help` | [01](01-first-lab-vmware.md) · [02](02-aws-landing-zone.md) · [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) · [08](08-backups-you-can-trust.md) · [10](10-compliance-scans.md) · [11](11-fips-140-mode.md) · [12](12-private-access-vpn.md) · [13](13-day-2-operations.md) · [14](14-ai-agents-and-mcp.md) |

### Tooling

| Command | Scenarios that run it |
|---|---|
| `cs install` | [03](03-gcp-private-gke.md) · [04](04-azure-private-aks.md) · [05](05-local-kubernetes.md) · [10](10-compliance-scans.md) · [12](12-private-access-vpn.md) · [14](14-ai-agents-and-mcp.md) |
| `cs deps status` | [02](02-aws-landing-zone.md) |
| `cs deps install` | [02](02-aws-landing-zone.md) |
| `cs deps image` | [02](02-aws-landing-zone.md) |
| `cs deps bundle` | [02](02-aws-landing-zone.md) |
| `cs deps runtime` | [02](02-aws-landing-zone.md) |

<!-- coverage-matrix:end -->
