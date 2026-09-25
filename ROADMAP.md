# cloudseed roadmap

This is where cloudseed is and where it is going next. It is a direction, not a promise of dates. Tell us what matters
to you in [Discussions](https://github.com/nimeshbuilds/cloudseed/discussions) or with a
[feature request](https://github.com/nimeshbuilds/cloudseed/issues/new/choose).

## Where 0.1 stands

| Area | Status in 0.1.0 |
|---|---|
| Landing zones | AWS, GCP and Azure stacks (network, NAT, hardened bastion, security baseline, remote state) and the same shape on local VMware Fusion Pro / Workstation Pro VMs |
| Kubernetes | private EKS, GKE and AKS; RKE2 or kubeadm on VMware; node add, remove and scale |
| Platform | a catalog of 73 pinned Helm/kustomize items in 10 groups, installed with dependencies and per-target values |
| Operations | Velero backups and restore drills, Chaos Mesh suites with verdicts, CIS/STIG/kubescape/trivy/prowler scans, FIPS 140 mode, OpenVPN and Tailscale access, FinOps estimates, fifteen-deep undo, audit trail and troubleshooting |
| Interfaces | CLI, local web console, MCP server (30 tools), agentic mode with the built-in agent, Claude Code, Codex, Gemini or Grok |
| Verification | about 3,400 unit tests, mocked `terraform test` suites for every cloud stack, 15 documented scenarios with scripts; VMware scenarios verified live, cloud scenarios verified with `--dry-run` (render + `terraform validate`) |

## Next (0.2)

- **Release artifacts**: publish the single-binary bundle (`cloudseed deps bundle`) for macOS and Linux on GitHub
  Releases with SHA-256 checksums, so trying cloudseed no longer needs a git clone.
- **Recorded cloud runs**: run the AWS, GCP and Azure scenarios against real accounts and publish the evidence next
  to each scenario page, alongside the existing dry-run verification.
- **Azure flow logs**: manage VNet flow logs (the successor of NSG flow logs) so Azure matches the logging on AWS
  and GCP.
- **GCP guard rails**: optional organization-policy constraints for projects that cloudseed's baseline owns.
- **Scenario CI**: run the local scenarios on a self-hosted runner with VMware so they are verified on every release,
  not only before it.
- **Docs**: more diagrams in `cloudseed explain`, and a troubleshooting page per failure signature that `troubleshoot`
  recognises.

## Later

- **Packaging**: a Homebrew tap and a PyPI package on top of the release binaries.
- **Policy as code**: an opt-in enforce mode for the `kyverno-policies` pod-security baseline, which runs in audit
  mode today.
- **More local hypervisors**: the VMware target is built on cloudseed's own Terraform provider; the same approach
  could cover other desktop hypervisors if there is demand.
- **Windows hosts**: VMware Workstation on Windows is experimental today because Ansible has no native Windows control
  node; a supported path (for example through WSL) is being explored.

## Not planned

- **AWS China and the isolated (ISO) regions.** Their partitions and service availability differ too much to support
  well today.
- **Spot or preemptible capacity created by cloudseed.** cloudseed creates on-demand nodes (its Karpenter NodePool
  asks for on-demand capacity too); spot capacity is a change you make outside cloudseed.
- **Hosted or SaaS control plane.** cloudseed runs on your machine and keeps its state there or in your own cloud
  account. There is no cloudseed server, account or telemetry, and that will not change.

## Known limits today

These are documented in `cloudseed help` and [the manual](https://nimeshbuilds.github.io/cloudseed/guides/manual/#notes-and-known-limits), and some are on the list above:

- The AWS account baseline (CloudTrail, S3 public-access block, password policy) belongs to one environment per
  account, and the regional baseline (GuardDuty, Access Analyzer, EBS default encryption) to one per account and
  region; later environments turn them off with `--var`.
- GCP's `_Default` log retention and Data Access audit logs are project-wide and stay in place after a destroy.
- Azure Defender pricing and Ubuntu Pro FIPS image terms are subscription-wide; a subscription allows five Activity
  Log diagnostic settings.
- On VMware, environments without their own `--cidr` share the built-in host-only network, so only one of them can
  have VMs at a time.
- `cloudseed finops cloud` reads AWS Cost Explorer and Azure Cost Management directly; GCP needs a BigQuery billing
  export first.
- cloudseed has not had an independent security audit.
