---
name: cloudseed-finops
description: Cost analysis and savings with the cloudseed CLI - `cloudseed finops` (estimate from inventory, actual cloud bill, OpenCost Kubernetes allocation, saved reports) and the levers cloudseed offers (node scaling, VPA/Goldilocks, KEDA, kube-green, NAT/LB choices). Use when the user asks what things cost, why the bill is high, or how to save money.
---

# cloudseed FinOps

## Get the numbers (deterministic)
- `cloudseed finops estimate [cloud --env X]`: monthly estimate from cloudseed's inventory (list prices). Always available, offline. Usage-billed services (GuardDuty, Security Hub, AWS Config, Log Analytics) are priced at a small environment's volume and Defender per VM / storage account at list price: say so when they matter.
  It prices a saved environment: for one that does not exist yet, run `cloudseed setup <cloud> --env X ... --dry-run` first
  (MCP: `cloudseed_setup` with `dry_run=true`; offline, no credentials, creates nothing), then the estimate. A plan
  (`--preview`, or `cloudseed_setup` without `apply`) keeps nothing and needs cloud credentials.
- `cloudseed finops cloud --days 30`: actual bill by service (AWS Cost Explorer / Azure Cost Management; GCP requires a BigQuery billing export).
- `cloudseed finops k8s --by namespace|controller|pod|label:<key> --window 7d`: OpenCost allocation with efficiency % (`cloudseed platform install finops` first).
- `cloudseed finops report --save`: everything into `<workdir>/finops/latest.json` - read it with `cloudseed inventory` context in mind.

## How to analyze
1. Compare estimate vs actual: a big gap means resources outside cloudseed (check `cloudseed inventory`) or data transfer / logging volume.
2. In Kubernetes, sort by total and look at efficiency: < 30% means over-requested CPU/RAM - propose Goldilocks recommendations
   (`cloudseed platform install goldilocks`, label the namespace `goldilocks.fairwinds.com/enabled=true`), then VPA in Auto mode for dev.
3. Idle-by-schedule workloads: kube-green SleepInfo (`cloudseed platform install kube-green`); event-driven: KEDA scale-to-zero.
4. Node level: fewer/smaller nodes via `cloudseed node remove` or `cloudseed setup ... --var kubernetes_node_size=...`;
   cloud: `single_nat_gateway=true`, delete unused VPN/K8s (`--var enable_vpn=false`).
   cloudseed creates on-demand / regular nodes only: the EKS node group is ON_DEMAND, the GKE and AKS pools have no spot
   or preemptible setting, and the Karpenter NodePool it installs asks for on-demand capacity. There is no cloudseed
   variable or command for spot: it is a manual change outside cloudseed (on EKS with Karpenter, the user's own
   NodePool with `karpenter.sh/capacity-type In [spot]` - the IAM policy and the interruption queue already support it).
   Label such a saving "not managed by cloudseed", with no cloudseed command and no cloudseed estimate.
5. Always show the user the concrete command for each saving and its estimated monthly impact; never destroy anything
   yourself. When a saving has no cloudseed command, say so - never invent a `--var`.

## Operational workflows across interfaces

Use `cloudseed ops list --json` for the installed contract before selecting parameters. The CLI form is
`cloudseed ops ACTION <cloud> --env <name> --params '{...}' --json`; MCP exposes `cloudseed_ops_ACTION` with
hyphens replaced by underscores and individual JSON fields. The console uses All actions → Operations & readiness.
Preview changes before `--approve` / MCP `confirm:true`, honoring explicit authorization already given by the user.

- `health`/`network` use local evidence by default; `live:true` queries deployed resources. An active network probe
  additionally needs `active:true` and approval, creates a temporary workload and reports its cleanup.
- `profile` previews lab/team/production topology and incomplete costs. `spec-export`, `spec-validate`, `spec-diff`
  and `spec-import` handle a versioned document without credentials/keys/state/runtime paths. Import/profile approval
  saves configuration only; Terraform apply, platform installs and backup schedules are separate approved actions.
- `policy-check` shows budget coverage and destructive plan actions. Never invent a complete estimate or suppress
  an unknown cost to satisfy a budget. `expiry-cleanup` requires saved elapsed expiry, saved opt-in and explicit
  approval for the exact environment; it never schedules future destruction or purges recovery state.
- `drift` is read-only. `upgrade-plan` needs an exact supported version, recent completed backup and operator
  compatibility review; `upgrade-apply` takes the fresh saved plan and repeats identity/readiness gates. It has no
  automatic downgrade guarantee.
- `recovery-plan`/`recovery-test` use a separate restricted namespace; review network isolation and external effects.
  Inspect object/data/volume coverage, measured RTO/RPO and asynchronous cleanup. Do not equate an object restore
  with proven application/database recovery.
- `acceptance` is preview-only without explicitly supplied sandbox identity, region, estimate, deadline and SSH
  source. Live execution additionally needs live + allow_cloud_changes + approval; retain cleanup evidence.
- `release-verify` checks a trusted digest and optional GitHub attestation without executing the artifact. A local
  digest match without verified provenance stays incomplete. `credentials-backend` can migrate storage to an
  available native keychain; never read or print credential values.

Follow scenarios 16–19 and the interface/coverage guide for complete workflows. Reports may remain INCOMPLETE when
live accounts/tools or manual reviews are absent. State the checks actually run and the limits of their evidence.
