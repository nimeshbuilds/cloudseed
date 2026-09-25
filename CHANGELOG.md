# Changelog

All notable changes to cloudseed are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While cloudseed is 0.x, a minor release may change
commands or defaults; such changes are called out under **Changed**.

## [Unreleased]

### Changed

- Redesigned GitHub Pages with a white-and-blue documentation theme, interactive architecture previews, clearer
  guide entry points, and consistent SVG/PNG branding. Added an end-to-end engineering review and prioritized roadmap.
- Build strict documentation on pull requests, explicitly install Node for tests, and retain failing CI logs.
- Upgrade the container to Python 3.14 and the VMware provider to Terraform Plugin Framework 1.19 (Go 1.25 minimum).
- Test source Python 3.9/3.12/3.14, native amd64/arm64 containers, Linux/macOS standalone binaries, and Ansible installation/playbook syntax in CI. Run provider tests with the Go race detector.

### Fixed

- MCP stop/restart with long process paths, local server startup with slow DNS, and console job completion metadata ordering.
- Explicit GCP credential diagnostics, Azure scanner login preflight, and VMware node/provision validation ordering.
- Host-dependent test fixtures and dry-run scenario assumptions that failed across the Linux/macOS Actions matrix.
- Preserve packaged assets when detached MCP/console services and console jobs outlive their launching process.
- Keep generated NIC MAC addresses unknown until creation with the updated Terraform framework.
- Refuse environment mutations when their lock cannot be acquired or recorded, including unsupported native Windows locking.
- Preserve recoverable VMware state on disk/cleanup failures, verify a VM is stopped before removing its bundle, and report actual disk capacity.
- Bound console event-stream memory for slow readers while preserving replay, gap markers and job completion.

## [0.1.0] - 2026-09-24

The first public release.

### Added

- **Landing zones on three clouds, one command each.** `cloudseed setup aws|gcp|azure` builds a VPC/VNet with public,
  private (and on AWS isolated data) subnets, NAT, flow logs, a hardened bastion reachable only from your IP, and a
  security baseline: CloudTrail, GuardDuty, Access Analyzer, EBS default encryption and optional Security Hub on AWS;
  log retention and Data Access audit logs on GCP; Activity Log to Log Analytics and optional Defender on Azure.
  Remote state in versioned, encrypted, private S3 / GCS / Azure Storage, or local state.
- **The same shape on your laptop.** `cloudseed setup vmware` creates a NAT'd bastion and private VMs on VMware
  Fusion Pro 13+ or Workstation Pro 17+ from official Ubuntu or Debian cloud images, through cloudseed's own Terraform
  provider (`providers/vmdesktop`).
- **Kubernetes.** Private EKS, GKE and AKS with workload identity and control-plane logging, or RKE2 / kubeadm on
  VMware; `cs node add|list|remove|scale`; `cs k8s kubeconfig`; `cs kubectl`, `cs helm` and `cs k9s` with a per-environment
  kubeconfig and an automatic SSH tunnel through the bastion for private endpoints; `cs env use` to pick the cluster.
- **Platform catalog.** `cs platform install` with 73 pinned items in 10 groups (basek8s, scaling, data, ai, agentic,
  finops, devsecops, security, resilience, chaos): ArgoCD, kube-prometheus-stack, Loki + Alloy, OpenTelemetry,
  cert-manager, Gateway API + Envoy Gateway, external-secrets, KEDA, Karpenter, MinIO, CloudNativePG, Strimzi, Trino,
  KServe, vLLM, Ollama, kagent, Istio, Falco, Velero, Chaos Mesh and more. Cloud prerequisites (buckets, identities)
  are created by the environment's own Terraform stack; `cs platform ui` exposes dashboards; `cs platform template
  gitlab-ci` writes a CI pipeline.
- **Resilience.** `cs dr backup|restore|schedule|test` with Velero, including an automated restore drill that verifies
  every object and a volume's data and reports the measured restore time.
- **Chaos engineering.** `cs chaos run basic|network|stress|full` with Chaos Mesh, steady-state hypotheses and
  PASS / FAIL / INCONCLUSIVE verdicts, against a canary or your own Deployment (`--target`), with JSON and Markdown
  reports.
- **Compliance and security scans.** `cs scan cis|kube|images|host|stig|cloud|fips|all` with kube-bench, kubescape,
  trivy, OpenSCAP (CIS and DISA STIG profiles) and prowler, with saved reports.
- **FIPS 140 mode** (`--var fips_mode=true`): FIPS endpoints, FIPS node images, FIPS-only SSH and VPN algorithms,
  RSA-4096 keys, TLS 1.2+ with FIPS ciphers on the shared Gateway, catalog items tiered by FIPS compatibility, and
  `cs scan fips` to verify it end to end.
- **Private access.** `--var enable_vpn=true` adds an OpenVPN host with its own PKI (`cs vpn add-user|users|revoke|
  connect|disconnect`) or a Tailscale subnet router.
- **Day-2 operations.** `cs update-ip`, `cs provision`, `cs status|output|inventory`, a per-environment audit trail
  and redacted logs, `cs troubleshoot` with known failure signatures and fixes, and `cs undo` with fifteen undo points
  per environment and fifteen for global settings (at most five of one kind).
- **FinOps.** `cs finops estimate` (offline, from the environment's own inventory), `cs finops cloud` (AWS Cost
  Explorer, Azure Cost Management), `cs finops k8s` (OpenCost allocation) and `cs finops report`.
- **Managed data services.** `cs databricks` and `cs snowflake` with per-environment connection profiles.
- **Web console.** `cs enable ui` starts a local, token-protected console on `127.0.0.1:7434` with a setup wizard,
  environment actions, the platform catalog, DR, chaos, scans, reports, agents, MCP, the credential vault and the
  help pages. Every action runs the same `cloudseed` command and streams its output.
- **MCP server.** `cs setup mcp` exposes every feature as an MCP tool (30 tools, plus resources and prompts) over
  Streamable HTTP on loopback with a bearer token, or stdio, and connects Claude Code, Claude Desktop, Codex, Cursor,
  Windsurf, Gemini CLI and VS Code. Destructive tools require `confirm=true`.
- **Agentic mode.** `cs agentic "<task>"` with the built-in agent (Claude API) or Claude Code, Codex, Gemini or Grok;
  a deterministic "headliner" research brief; bundled Agent Skills; credentials stripped from the agent and served to
  child commands over a per-session socket; output redacted; human-only commands refused in agent sessions.
- **Explain everything.** `cs explain <feature|target|command|item>` shows how each capability is implemented, which
  files and cloud resources it uses and where its state lives. `cs help` covers every command, topic, variable and
  output.
- **Dependencies your way.** Install tools locally (`cs deps install`, SHA-256-verified official releases or
  Homebrew), run everything in a Docker or Podman image (`--runtime container`), or build a single binary
  (`cs deps bundle`).
- **Credential vault.** `cs creds set|list|unset|clear` keeps cloud keys and API tokens in a local 0600 file used by
  every command, the console and the MCP server.
- **Project.** Apache-2.0 license, documentation site with a quick start and 15 step-by-step scenarios, contribution
  guide, security policy and CI: unit tests on Python 3.9 and 3.12 on Linux and macOS, `terraform fmt`, `validate` and
  the mocked `terraform test` suites, `go vet`/`test`/`build` for the VMware provider, and the scenario scripts in
  dry-run mode.

[Unreleased]: https://github.com/nimeshbuilds/cloudseed/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nimeshbuilds/cloudseed/releases/tag/v0.1.0
