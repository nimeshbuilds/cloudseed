---
title: "Changelog - cloudseed v0.2.0 highlights"
description: "Cloudseed v0.2.0 adds Well-Architected assessments, operational readiness, trusted runtime releases, expanded scenarios and runtime fixes."
---

# Changelog

The full, detailed history is in [CHANGELOG.md](https://github.com/nimeshbuilds/cloudseed/blob/main/CHANGELOG.md) on
GitHub. cloudseed follows [Semantic Versioning](https://semver.org/); while it is 0.x, a minor release may change
commands or defaults, and such changes are called out.

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
