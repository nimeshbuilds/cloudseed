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
