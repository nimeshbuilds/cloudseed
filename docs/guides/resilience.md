---
title: "Resilience - Velero backups, DR drills and chaos engineering with verdicts"
description: "Velero backups with the bucket and identity created for you, automated DR drills with a verdict, and Chaos Mesh experiments with PASS/FAIL reports."
---

# Resilience: backups, DR drills and chaos

`cs dr test` backs up and restores a generated sample workload and reports which checks passed.
`cs chaos run` measures a generated canary under injected faults; use `--target` to test a selected Deployment.
Results apply to that sample or target and the checks actually performed. Use the
[application recovery workflow](../scenarios/18-upgrades-and-recovery.md#step-4-rehearse-an-application-restore) to assess a selected application backup.

## Disaster recovery with Velero

```bash
cs platform install velero      # or let the first cs dr command install it
cs dr test                      # the automated drill: PASS or FAIL, with the measured restore time
```

### What gets installed

`velero` is part of the `resilience` group (with kured for safe node reboots and the descheduler). Before the chart is
installed, cloudseed creates what Velero needs in your cloud **through the environment's own Terraform stack**, with
the plan shown and your approval:

| Target | Backup storage | Identity |
|---|---|---|
| AWS | S3 bucket: versioned, encrypted, private | IRSA role for the velero service account |
| GCP | GCS bucket | GKE Workload Identity |
| Azure | Blob storage | Azure workload identity + a snapshot role |
| VMware | the in-cluster MinIO | - |

Volumes are backed up by Velero's node agent (file-system backup). On local clusters the local-path StorageClass
creates volumes the node agent can back up.

### Back up, schedule, restore

```bash
cs dr status                                          # Velero, backup location, schedules
cs dr backups                                         # the backups that exist
cs dr backup before-upgrade --namespaces shop,payments
cs dr schedule nightly --cron "0 2 * * *" --ttl 720h  # 02:00 UTC every night, kept 30 days
cs dr restore before-upgrade
```

- Cron expressions are evaluated by Velero in **UTC**; `--ttl` is a Go duration (`720h` = 30 days, the default).
- `--no-wait` returns right away instead of waiting for Velero to finish.
- Names are Kubernetes names: lower-case letters, digits, `-` and `.`.
- `dr status` and `dr backups` need no Velero CLI. The other commands use the Velero CLI matching the server's
  version, fetched into `~/.cloudseed/bin` only on your own run, never from an agent session.
- `cs undo` deletes a backup or schedule you just created, and rolls a restore back to the backup taken just before it.

### The DR drill

```bash
cs dr test
```

```mermaid
flowchart TB
    a["create a sample workload<br/>Deployment, ConfigMap, Secret,<br/>Service, 1Gi volume + random file"] --> b["back it up"]
    b --> c["delete the namespace"]
    c --> d["restore"]
    d --> e["verify every object<br/>and the file's contents"]
    e --> f["PASS / FAIL<br/>+ restore time"]
```

The drill passes only when every object came back and the random file on the volume is intact, with Completed
PodVolumeBackups and PodVolumeRestores. It exits 1 on FAIL and saves its report to
`<workdir>/dr/drill-<run>.json` and `.md`. Afterwards it deletes its namespace and backup.

| Flag | Effect |
|---|---|
| `--keep` | keep the drill namespace and its backup for inspection |
| `--no-volume` | skip the volume |
| `--volume` | require the volume test (needs a default StorageClass or an unclassed PersistentVolume of 1Gi+) |

## Chaos engineering

```bash
cs chaos list          # every experiment with its steady-state hypothesis
cs chaos run           # the basic suite against a canary cloudseed deploys for you
cs chaos report        # the last verdict table
```

Chaos Mesh is installed on first use (after asking; `--auto-approve` to skip the question). `run` deploys a canary
(3 replicas, a PodDisruptionBudget, a Service and a probe pod) or targets your own Deployment, then runs the
experiments one by one.

### Suites and experiments

| Suite | Experiments | What must hold |
|---|---|---|
| `basic` | `pod-kill`, `pod-failure`, `container-kill` | a Deployment replaces or restarts pods |
| `network` | `network-delay`, `network-loss`, `network-partition`, `dns-error` | requests survive latency and loss; outages recover |
| `stress` | `cpu-stress`, `memory-stress`, `time-skew` | pods keep serving under pressure |
| `full` | all of the above | |

Every experiment has a **steady-state hypothesis**: availability is sampled from the probe pod while the fault is
injected, the fault is lifted, and the time to full recovery is measured. For example, `pod-kill` needs at least 50%
availability during the fault and full recovery within 90 seconds. `cs chaos list` shows every threshold.

### Verdicts you can trust

- An experiment **PASSes** only when both the availability floor and the recovery bound hold.
- A fault Chaos Mesh never actually injected is an **ERROR**, never a pass.
- The run is **PASS** only when every experiment ran and passed, **FAIL** when one failed or errored, otherwise
  **INCONCLUSIVE**. The exit code is 0 only for PASS.
- The verdict table is printed and saved to `<workdir>/chaos/report-<run>.json` and `.md`.

### Target your own workload

```bash
cs chaos run basic --target shop/api:8080       # namespace/deployment[:port]; pods WILL be killed, so it asks first
cs chaos run network-loss cpu-stress --duration 2m
cs chaos stop                                    # stop everything and remove the canary
```

| Flag | Effect |
|---|---|
| `--duration T` | fault time per experiment: `45s` (default), `2m`, from 15 seconds to 1 hour |
| `--replicas N` | canary replicas, 2 to 20 (default 3) |
| `--keep` | keep the canary namespace afterwards (`cs chaos stop` removes it) |
| `--auto-approve` | do not ask before faulting your own workload, and install Chaos Mesh when missing |

!!! warning "Faults are real"
    `--target` kills pods and degrades the network of a real Deployment. Run it where that is acceptable, and read
    the plan before you approve.

## In the web console

The **Resilience** view has the same actions as buttons: *Run DR drill*, *Backup now*, *Restore*, *Schedule*, the chaos
suites, *My workload*, *Stop all*, and every scan. Reports appear under **Reports**. See the
[Web console guide](web-console.md).

## Read scan reports alongside recovery evidence

Security scans and [Well-Architected assessments](well-architected.md) save JSON and Markdown under
`<workdir>/scans/`. Both retain the saved findings, details and remediation; the terminal shows a summary.
The console's **Reports** view exposes findings and coverage limits. A scan result describes the checks performed:
it does not establish that every resource is secure or that an application can recover.

Agents can read full saved artifacts through `cs evidence list|read` or MCP `cloudseed_evidence`, without direct
filesystem access or running another scan. Follow the returned pages with the same revision until `complete=true`;
see the [evidence walkthrough](../scenarios/14-ai-agents-and-mcp.md#step-7a-explain-a-saved-scan-without-running-it-again).
That flag means the artifact was fully read. `unknown=0` counts one category of observations; neither establishes
complete scan coverage. Use the report's recorded time, diagnostics and explicit coverage limits.

| Scan result | Exit code | Interpretation |
|---|---|---|
| `PASS` | `0` | The performed checks satisfy that scanner's policy; inspect remaining coverage limits. |
| `N/A` | `0` | The scanner or profile does not apply, such as FIPS checks on a non-FIPS environment. |
| `FAIL` | `1` | Findings breach the scanner's policy. Review unresolved evidence too. |
| `INCOMPLETE` | `3` | Required evidence is missing, manual, unknown or partial. |
| Invalid arguments | `2` | Correct the command input before retrying. |

`scan all` also exits 1 when an action cannot run. A failed result takes precedence over incomplete evidence.
`INCOMPLETE` is reserved for a gap in a requested, applicable assessment: an access error, missing/malformed
results, an unreachable runtime, or a required control awaiting manual verification. It is not a generic warning.
Disabled components and explicitly inapplicable or excluded controls are `N/A`; informational output does not block
otherwise completed checks. If no checks apply, the result is `N/A`, not a pass. Evidence of a real failure still
produces `FAIL` even when other checks could not be completed.

An `UNKNOWN` finding explains the specific evidence gap and how to resolve it. For example, a missing saved
report names the report to collect, an expired report identifies the freshness problem, an unrecognized scanner
result identifies the unsupported field, and a manual control describes the review still needed. Read the finding's
detail and remediation plus scanner diagnostics before retrying; retrying alone cannot supply organisational evidence.

Scanners have individual policies: cloud CIS scans fail on every failed benchmark observation, including medium
and low severity; with no failures, manual/unknown checks, empty output and execution or coverage errors remain
incomplete. Cloud benchmarks cover an account, project or subscription, so findings may concern resources outside
the selected environment. DR drills and chaos experiments retain their separate verdict rules described above.
For AWS, an open network ACL finding concerns one subnet traffic control. Internet reachability also depends on
routing, public addressing and the applicable security rules; assess those together before concluding that a host
is exposed. See AWS's [network ACL guidance](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
and [internet gateway requirements](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html).

Run `cs scan cloud` before `cs scan architecture` to include its saved evidence. The architecture scanner's
`--max-age-days` controls how old that evidence may be; it never runs scans or drills automatically. Its recovery
check requires a complete, recent sample restore with verified volume contents. Application RTO/RPO and regional
recovery still need workload-specific tests.

## Related

- [Security, scans and FIPS](security-and-fips.md): CIS, STIG, vulnerability, cloud and FIPS scans
- [Well-Architected assessments](well-architected.md): saved configuration, recovery evidence and explicit unknowns
- Scenarios: [backups you can trust](../scenarios/08-backups-you-can-trust.md),
  [chaos engineering](../scenarios/09-chaos-engineering.md)
- `cs help dr`, `cs help chaos`, `cs explain dr`, `cs explain chaos`
