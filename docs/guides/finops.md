---
title: "FinOps - estimate, actual cloud bill and Kubernetes cost allocation"
description: "Estimate an environment's cost before you build it, read the actual AWS or Azure bill, and allocate Kubernetes cost by namespace with OpenCost."
---

# FinOps

Three views on money, all deterministic and saved so you (or an agent) can reason about them:

| View | Command | Source | Needs |
|---|---|---|---|
| **Estimate** | `cs finops estimate` | cloudseed's own inventory and config at on-demand list prices | nothing: offline, works right after a `--dry-run` |
| **Actual bill** | `cs finops cloud` | AWS Cost Explorer, Azure Cost Management | the cloud CLI and billing read access; GCP needs a BigQuery billing export (cloudseed tells you how) |
| **Kubernetes allocation** | `cs finops k8s` | OpenCost | `cs platform install finops` |
| **Everything** | `cs finops report --save` | all of the above | saved to `<workdir>/finops/latest.json` |

## Estimate before you build

```bash
cs setup aws --env demo --dry-run
cs finops estimate aws --env demo
```

```text
  ╭─ Estimate · aws-demo  (month, 730h at on-demand list prices) ──────────────╮
  │ bastion t3.micro x1           $7.59                                        │
  │ NAT gateway x1                $32.85                                       │
  │ public IPv4 x2                $7.30                                        │
  │ KMS key x1                    $1.00                                        │
  │ CloudTrail + logs (low vol.)  $3.00                                        │
  │ GuardDuty (low volume)        $5.00                                        │
  │ block storage ~10 GB          $0.80                                        │
  │                                                                            │
  │ total / month                 $57.54                                       │
  │                                                                            │
  │ VPC flow logs (30-day retention) are billed per GB ingested and stored     │
  │   in CloudWatch: not included.                                             │
  │ Prices are us-east-1 on-demand list prices. Data transfer and NAT          │
  │   processing are not included.                                             │
  ╰────────────────────────────────────────────────────────────────────────────╯
```

Default landing zones, estimated the same way (monthly, on-demand list prices, before data transfer):

| Target | Estimate | Biggest item |
|---|---|---|
| AWS (us-east-1) | about $58 | the NAT gateway ($32.85) |
| Azure (eastus) | about $55 | the NAT gateway ($32.85) |
| Google Cloud (us-central1) | about $11 | the e2-micro bastion ($6.13) |
| VMware | $0 | runs on your machine |

A Kubernetes cluster, a VPN host or FIPS images add to these; run the estimate after changing the configuration.
Usage-billed services (GuardDuty, Security Hub, AWS Config, Log Analytics) are priced at a small environment's volume.

## The actual bill

```bash
cs finops cloud --days 7
```

The bill by service from the provider, for the environment's account or subscription. Compare it with the estimate: a
large gap usually means resources outside cloudseed (check `cs inventory`), data transfer or logging volume.

## Kubernetes cost allocation

```bash
cs platform install finops                     # OpenCost + Prometheus (+ metrics-server, Goldilocks)
cs finops k8s --by namespace --window 7d
cs finops k8s --by controller --window 24h
```

Allocation by namespace, controller, pod or label, with an efficiency figure so idle requests stand out. Efficiency
below about 30% means over-requested CPU or memory.

## Save and ask for savings

```bash
cs finops report --save
cs agentic "look at my finops report and propose the top 5 savings"
```

The `cloudseed-finops` skill knows the report format and the levers cloudseed offers:

| Lever | How |
|---|---|
| Right-size pods | Goldilocks recommendations (`cs platform install goldilocks`), then VPA |
| Scale to zero | KEDA for event-driven workloads; kube-green sleep schedules for office-hours environments |
| Fewer or smaller nodes | `cs node remove`, `cs node scale`, `--var kubernetes_node_size=...` |
| One NAT gateway | `--var single_nat_gateway=true` (the AWS default; per-AZ NAT is more resilient and costs more) |
| One load balancer | the shared Gateway instead of a load balancer per app |
| Drop what is idle | `--var enable_vpn=false`, `--var enable_kubernetes=false`, or `cs destroy` for a whole environment |

!!! note "Spot capacity"
    cloudseed creates on-demand nodes only. Spot or preemptible capacity is a change you make outside cloudseed, and
    the agent labels it that way.

## In the web console

Each environment card has a **Cost** button that runs the estimate, and the **Agents & MCP** view can run the savings
task. See [Web console](web-console.md).

## Related

- [Scenario 15 - web console and FinOps](../scenarios/15-web-console-and-finops.md)
- `cs help finops`, `cs explain finops`
