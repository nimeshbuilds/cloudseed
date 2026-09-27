---
title: "Changelog - cloudseed v0.2.3 highlights"
description: "Cloudseed v0.2.3 improves agent command discovery, complete saved-evidence access and retained scanner diagnostics."
---

# Changelog

The full, detailed history is in [CHANGELOG.md](https://github.com/nimeshbuilds/cloudseed/blob/main/CHANGELOG.md) on
GitHub. cloudseed follows [Semantic Versioning](https://semver.org/); while it is 0.x, a minor release may change
commands or defaults, and such changes are called out.

## v0.2.3 - 2026-09-27

This version includes the agent and saved-evidence improvements from the unpublished v0.2.2 candidate.

`cs usage report`, MCP `cloudseed_usage` and the console show usage metadata for Cloudseed tasks and MCP activity.
Optional ccusage analysis reads only Cloudseed-generated inputs. Missing metrics have explanations rather than
invented zeroes, and estimated cost is separate from invoices and subscription quota. See [agent usage](../guides/usage.md).

The **Context brief** gives an agent environment facts, tool status and saved evidence locations before its task.
The compatible `headliner` setting controls this deterministic research; `cs disable headliner` turns it off.
See [the Context brief](../guides/agentic.md#the-context-brief).

Agents receive private `cloudseed` and `cs` launchers for the exact installation running the task, including
standalone binaries absent from `PATH`. An absolute launcher path provides a fallback when the agent's shell
resets `PATH`. This avoids command-discovery failures without installing another copy or granting broad file access.

`cs evidence list/read` and MCP `cloudseed_evidence` expose saved reports and diagnostic logs through redacted,
revision-bound pages. Follow every page before explaining the report, and inspect its observation time, scope,
diagnostics and coverage limits. `unknown=0` does not prove every resource or control was assessed. The interface
excludes arbitrary files, credentials and Terraform state. See [saved reports over MCP](../guides/mcp.md#read-saved-reports)
and [scenario 14's report-review exercise](../scenarios/14-ai-agents-and-mcp.md#step-7a-explain-a-saved-scan-without-running-it-again).

New cloud scans retain bounded, redacted diagnostic excerpts and a private `prowler.log`, including failed or
timed-out collection, with explicit omitted-output counts. Historical scanner output that was discarded cannot
be recovered. Zero-error counters and ordinary prose mentioning errors no longer create false incomplete verdicts.
The built-in agent preserves full evidence pages and reports interrupted or truncated tool output.

macOS signing retries recognized Apple timestamp-service failures up to three times per signing operation.
Other signing failures still stop immediately; secure timestamps, hardened runtime and final verification remain
required. Developer ID signing remains separate from notarization. These improvements do not establish live
deployment acceptance across all cloud providers.

## v0.2.2 - unpublished candidate

The release pipeline stopped after a runtime dependency packaging failure on Intel macOS. No v0.2.2 release assets
were published. Its tag is retained, and the agent and saved-evidence improvements continue in v0.2.3.

## v0.2.1 - 2026-09-26

Standalone binaries now include trusted CA certificates for public-IP discovery and HTTPS downloads on a fresh
machine. AWS, GCP and Azure setup share the fix through the CLI, console, MCP and agent skills. Setup and
`update-ip` now explain certificate and connectivity failures. Explicit CA overrides and saved SSH allow-lists
remain authoritative. See [automatic public-IP troubleshooting](../guides/troubleshooting.md#automatic-public-ip-detection).

Standalone releases also carry portable source for installing `cloudseed` and `cs` on Linux bastions. Provisioning
checks both commands and installs kubectl, Helm and k9s when Kubernetes and tools are enabled. The controller's
environment records, state, SSH keys, kubeconfig and cloud credentials stay on the controller. See
[bastion installation and repair](../guides/dependencies-and-runtimes.md#cloudseed-on-the-bastion).

Explicit `--local-context` uses the invoking host's already-authorized kubeconfig for kubectl, Helm or terminal k9s.
kubectl/Helm expose the same choice through MCP, agents and the console, with target confirmation. It validates a
selected context and HTTPS/TLS configuration; it does not grant provider permissions, import an environment or
create Cloudseed Undo entries. Private cluster access from the original controller also prepares kubectl before
configuring the bastion tunnel and reports a kubeconfig update failure instead of claiming the tunnel is ready.
See [Kubernetes access and bastions](../guides/kubernetes-access.md).

Scan reports now retain detailed findings and remediation, including lower-severity cloud findings and manual
checks. Empty and partial scan evidence remains incomplete, with exit code 3. The console exposes report details,
coverage and preview limits with full saved artifacts. Architecture correctly skips Kubernetes diagnostics when
Kubernetes is explicitly disabled. See [scan reporting](../guides/resilience.md),
[Well-Architected evidence](../guides/well-architected.md) and the expanded
[AWS cloud-scan walkthrough](../scenarios/10-compliance-scans.md#step-6-the-cloud-account-cloud-environments).

macOS release packaging uses Apple Developer ID signing and verifies the expected publisher, hardened runtime and
secure timestamp before testing and attesting the signed bytes. Apple signing and notarization are separate;
this release workflow does not perform notarization. Automated installation and regression checks do not establish
live deployment acceptance across all cloud providers.

## v0.2.0 - 2026-09-25

Shared operations now cover health/network evidence, real topology profiles, portable specifications, budget/plan
policy, explicit expiry cleanup, drift, guarded upgrades, application recovery, sandbox acceptance, native keychain
storage and release verification across CLI/MCP/UI/skills. [Scenarios 16–19](../scenarios/index.md#operational-readiness-walkthroughs)
and the [coverage guide](../scenarios/interfaces-and-coverage.md) describe what is locally tested and what still
requires live cloud evidence. See the full changelog for implementation and compatibility details.

- **Well-Architected assessments** evaluate saved configuration and local evidence across AWS, GCP, Azure and
  VMware, through CLI, MCP, console and skills. Missing evidence remains explicit.
- **Trusted runtime releases** build and test Linux/macOS amd64/arm64 binaries and amd64/arm64 containers.
  Version-tag publication includes checksums, manifests, complete dependency inventories and signed provenance.
- **Runtime fixes** preserve VMware recovery state, enforce environment locks, bound console streams, retain
  bundled service assets, and repair tunnel detection and MCP cleanup.
- **Documentation and scenarios** use the new white-and-blue Pages design and cover all operations through
  CLI, agent, MCP and UI routes in 19 scenarios.

Download versioned artifacts from [GitHub Releases](https://github.com/nimeshbuilds/cloudseed/releases) and follow
[scenario 19](../scenarios/19-acceptance-and-releases.md) to verify their integrity and provenance.

## v0.1.0 - 2026-09-24

The first public release.

### Landing zones

- **One command per cloud.** `cloudseed setup aws|gcp|azure` builds a private network with NAT and flow logs, a
  hardened bastion reachable only from your IP, and a security baseline: CloudTrail, GuardDuty, Access Analyzer, EBS
  encryption by default and optional Security Hub on AWS; log retention and Data Access audit logs on GCP; Activity Log
  to Log Analytics and optional Defender on Azure. [Concepts](../getting-started/concepts.md)
- **The same shape on your laptop.** `cloudseed setup vmware` on VMware Fusion Pro 13+ or Workstation Pro 17+, driven by
  cloudseed's own Terraform provider. [Quickstart](../getting-started/quickstart.md)
- **Remote state bootstrapped for you** in versioned, encrypted, private S3, GCS or Azure Storage, or local state.
- **Idempotent `setup`, targeted `destroy`,** `update-ip` for a changed public IP, and Ansible hardening of every host
  after each apply.

### Kubernetes and the platform

- Private **EKS, GKE and AKS**, or **RKE2 / kubeadm** on VMware, with `cs node add|list|remove|scale`, `cs k8s`, and
  `cs kubectl|helm|k9s` that tunnel through the bastion to private endpoints. [Platform](../guides/platform.md)
- A **catalog of about seventy pinned components in ten groups**: GitOps, observability, Gateway API, certificates,
  secrets, autoscaling, data, AI, agentic, FinOps, DevSecOps, security, resilience and chaos. Cloud prerequisites are
  created through the environment's Terraform stack; `cs platform ui` exposes every dashboard.
- **Databricks and Snowflake** profiles per environment, and a GitLab CI template.

### Resilience, security and compliance

- **Velero backups** with an automated **DR drill** that proves a restore works. [Resilience](../guides/resilience.md)
- **Chaos engineering** with steady-state hypotheses and PASS / FAIL / INCONCLUSIVE verdicts.
- **Scans** with saved reports: CIS (kube-bench), NSA / MITRE (kubescape), vulnerabilities (trivy), host CIS and DISA
  STIG (OpenSCAP), cloud CIS (prowler) and FIPS verification. [Security](../guides/security-and-fips.md)
- **FIPS 140 mode** for a whole environment with one variable.
- **OpenVPN or Tailscale** private access. [VPN](../guides/vpn.md)

### Operations

- **Undo** for nearly every action, including a full destroy. [Undo and audit](../guides/undo-and-audit.md)
- An **audit trail**, redacted logs and an inventory for every environment, and `cs troubleshoot` with known failure
  signatures and fixes. [Troubleshooting](../guides/troubleshooting.md)
- **FinOps**: offline estimates, the actual cloud bill and OpenCost allocation. [FinOps](../guides/finops.md)
- **Dependencies your way**: verified local installs, a Docker / Podman image, or a single binary.
  [Dependencies](../guides/dependencies-and-runtimes.md)
- A local **credential vault** with hidden input. [Credentials](../guides/credentials.md)

### Interfaces

- A local, token-protected **web console** with every feature as forms and buttons. [Web console](../guides/web-console.md)
- An **MCP server** with 30 tools for Claude Code, Claude Desktop, Codex, Cursor, Windsurf, Gemini CLI and VS Code,
  with `confirm=true` gating every change. [MCP](../guides/mcp.md)
- **Agentic mode** with the built-in Claude agent, Claude Code, Codex, Gemini or Grok, a research brief, ten bundled
  skills, and credentials that never reach the agent. [Agentic mode](../guides/agentic.md)
- **Explain everywhere**: `cs explain` for how anything works, as terminal text, `--json`, a "?" beside everything in
  the web console, and `cloudseed_explain` / `cloudseed://explain/{query}` over MCP. [Explain](../guides/explain.md)
- **Built-in help** for every command, topic, variable and output, and a reference on this site generated from the
  code. [Reference](../reference/index.md)
