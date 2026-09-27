---
title: "Scenario 10: Kubernetes compliance scans - CIS, STIG, trivy, FIPS"
description: "Compliance scans with cloudseed: CIS Kubernetes Benchmark (kube-bench), kubescape, trivy image CVEs, OpenSCAP CIS and DISA STIG on hosts, and FIPS checks."
---

# 10 · Compliance scans

**Outcome:** the security scan suite runs against your cluster and hosts: the CIS Kubernetes Benchmark
(kube-bench, the right profile per distro), NSA + MITRE ATT&CK posture (kubescape), vulnerabilities in running images
(trivy), OpenSCAP CIS and DISA STIG profiles on the bastion and the nodes, and FIPS 140 verification; each with a
verdict, JSON and Markdown reports, and an exit code your CI can use.

!!! success "Verified live on VMware Fusion 13.6"
    [`tests/scenarios/10-compliance-scans.sh`](https://github.com/nimeshbuilds/cloudseed/blob/main/tests/scenarios/10-compliance-scans.sh)
    runs the security scans below against the scenario 05 cluster and its hosts with `CLOUDSEED_LIVE=1`. Without it, it runs
    the FIPS verification and the reports list offline and checks that the cluster and host scans say there is
    nothing to scan yet. `scan cloud` needs cloud credentials (see [04](04-azure-private-aks.md)).

| :material-clock-outline: Time | :material-cash: Cost | :material-signal-cellular-2: Level | :material-kubernetes: Needs |
|---|---|---|---|
| ~25 min | $0 on the local cluster | Intermediate | The cluster from [05](05-local-kubernetes.md) |

## What you'll build

```mermaid
flowchart LR
  cs["cs scan all"] --> cis["cis<br/>kube-bench<br/>rke2-cis-1.9 / eks / gke / aks"]
  cs --> kube["kube<br/>kubescape<br/>NSA + MITRE (+ CIS)"]
  cs --> img["images<br/>trivy-operator or trivy k8s"]
  cs --> host["host / stig<br/>OpenSCAP + SCAP Security Guide<br/>bastion, VPN host, local nodes"]
  cs --> fips["fips<br/>FIPS 140 verification"]
  cloud["cs scan cloud<br/>prowler CIS for the account"]
  cis & kube & img & host & fips --> rep["~/.cloudseed/envs/vmware-lab/scans/<br/>kind-run.json + .md, raw/"]
```

## Before you start

- The cluster from [05](05-local-kubernetes.md), selected with `cs env use vmware-lab`. The more you installed in
  [06](06-platform-in-one-command.md) and [07](07-data-and-ai-stack.md), the more there is to scan.
- kubescape and trivy are installed on first use; to fetch them up front:

```bash
cs install kubescape trivy
```

## Step 1: Know what each scan checks

```bash
cs help scan
cs explain scan
```

## Step 2: CIS Kubernetes Benchmark

```bash
cs scan cis
```

kube-bench runs as a Job with the benchmark for the distro (`rke2-cis-1.9` here; `eks-1.8.0`, `gke-1.9.0`, `aks-1.8`
on managed clusters) on the control plane and the nodes. The policy checks (RBAC, service accounts, network policies)
use a temporary read-only ClusterRole that is removed when the scan ends.

??? example "Expected output (abbreviated; your counts differ)"
    ```text
      ╭─ CIS Kubernetes Benchmark · vmware-lab ──────────────────────────────────────╮
      │ benchmark      rke2-cis-1.9                                                  │
      │ distro         rke2                                                          │
      │ pass           86                                                            │
      │ fail           7                                                             │
      │ warn           39                                                            │
      │ info           0                                                             │
      │                                                                              │
      │ top findings (7)                                                             │
      │ FAIL      1.1.12 Ensure that the etcd data directory ownership is ...        │
      │ ...                                                                          │
      │ verdict        FAIL                                                          │
      │ report         ~/.cloudseed/envs/vmware-lab/scans/cis-20260924-204512.json   │
      ╰──────────────────────────────────────────────────────────────────────────────╯
    ```

A lab cluster without `kubernetes_cis_profile=true` does not pass every control: the report lists each failing
control with its remediation. The exit code is 1 when the verdict is FAIL.

## Step 3: Posture and vulnerabilities

```bash
cs scan kube --framework nsa,mitre,cis-v1.10.0
cs scan images
```

- `kube` gives a compliance score per framework and the failing controls by severity. For continuous scanning:
  `cs platform install kubescape-operator`.
- `images` uses trivy-operator's reports when it is installed (`cs platform install trivy-operator`), otherwise a
  one-off `trivy k8s` scan of the running workloads.

## Step 4: The hosts: CIS and DISA STIG with OpenSCAP

```bash
cs scan host vmware --env lab --host bastion,k8s
cs scan stig vmware --env lab --host bastion
```

OpenSCAP and the SCAP Security Guide run on every SSH-reachable host you name (bastion, VPN host, local Kubernetes
nodes) and leave a score, the failed rules and an HTML report per host under `scans/openscap-<run>/`. Ubuntu 24.04
has STIG content; hosts without content for a profile (the AL2023 AWS bastion, the Debian 12 GCP bastion) report n/a.

## Step 5: FIPS verification and everything at once

```bash
cs scan fips vmware --env lab
cs scan all
cs scan reports --last 5
```

`scan fips` on an environment created without FIPS mode reports **N/A** (FIPS is chosen at creation; see
[11](11-fips-140-mode.md)), followed by how many of its checks would fail. On the deployed lab it checks more than the
configuration and the SSH key: every host over SSH (kernel FIPS mode, the OpenSSL FIPS provider, sshd's algorithms,
Ubuntu Pro FIPS), the cluster's nodes and each installed platform item's FIPS class, so most checks fail and the count
depends on what you have installed. `scan all` runs applicable security scans and prints a summary; it exits 1 when a
verdict is FAIL or a scan could not run.

??? example "Expected output of `cs scan fips vmware --env lab` on a non-FIPS environment (abbreviated)"
    ```text
      ╭─ FIPS 140 verification · vmware-lab ─────────────────────────────────────────────────╮
      │ ✖ config      fips_mode enabled for the environment   chosen at creation: cs setup    │
      │               <cloud> --var fips_mode=true (new environments only; ...)               │
      │ ✖ ssh         environment SSH key is FIPS-approved (RSA-4096; ECDSA only on GCP/VMware)│
      │ ✖ hosts       bastion: kernel FIPS mode (fips_enabled=1)   fips_enabled=absent         │
      │ ✖ hosts       bastion: OpenSSL FIPS provider active                                    │
      │ ...           (the same host checks for every node, then kubernetes and platform rows) │
      │ ○ platform    argocd: FIPS-compatible   runs on FIPS kernels; ...                      │
      │                                                                                        │
      │ N/A - vmware-lab is not a FIPS environment (FIPS is chosen at creation); N of M checks │
      │ would fail                                                                             │
      ╰────────────────────────────────────────────────────────────────────────────────────────╯
    ```

## Step 6: The cloud account (cloud environments)

```bash
cs scan cloud aws --env prod
```

prowler runs the newest CIS benchmark for the provider against the account, project or subscription of a cloud
environment (in an AWS FIPS environment, only its region, through the FIPS endpoints). `--framework` picks another
prowler compliance id.

You can complete this step on a base AWS landing zone with Kubernetes disabled. For example, for an existing
`aws-demo` environment:

```bash
cs scan cloud aws --env demo
cs scan architecture aws --env demo --profile lab --max-age-days 30
cs scan reports aws --env demo --last 5
```

Run the cloud scan first: architecture reads saved evidence and never starts a live scan itself. `--max-age-days 30`
accepts evidence at most 30 days old; it is not a scan schedule or a 30-day AWS activity query. Use `--profile production`
to discuss production availability requirements such as per-zone NAT gateways, without changing the deployment.

Cloud results cover the account/project/subscription selected by your credentials, including resources created outside
Cloudseed. AWS normally includes Prowler's scanned regions and global services, even when the environment belongs to
one region. The report records scope, failed and manual observations, check IDs, resources, explanations and remediation.
One check may produce several resource observations. A check title describes the desired state; read the detail to see
why the resource failed.

For cloud scans, any failed observation yields **FAIL / exit 1**. With no failures, manual/unknown observations,
empty output or detected execution errors yield **INCOMPLETE / exit 3**. A completed scanner process is not proof of
complete benchmark coverage. Keep real account findings visible: for example, missing root MFA requires the account
owner's attention, and a permissive NACL needs review alongside routing and security groups before concluding that a
private instance is publicly reachable. Review recommendations before changing a shared account or adding paid services.

**Agent:** “For aws-demo, run the cloud scan, then the lab architecture assessment with evidence age 30 days.
Explain every failed/manual finding, separate account-wide findings from known environment resources, and propose
changes without applying them.”

**MCP:** use `cloudseed_scan` with `{"kind":"cloud","cloud":"aws","env":"demo"}`, then
`{"kind":"architecture","cloud":"aws","env":"demo","profile":"lab","max_age_days":30,"json":true}`.
Complete any prerequisite tool installation through the normal host flow first.

**UI:** select aws-demo, run **Cloud CIS** from **Resilience → Scans**, then run the **Well-Architected** lab assessment.
Open both in **Reports**. Inspect status, severity, resources, evidence and remediation; use the full saved JSON/Markdown
when the preview says it is limited. Legacy reports may contain fewer normalized details; a new scan produces the
expanded report without rewriting older evidence.

## Step 7: Assess architecture using local evidence

```bash
cs scan architecture vmware --env lab --profile lab --max-age-days 30 --json
```

This separate assessment reads saved configuration and local evidence without querying the cluster or cloud,
installing tools or changing infrastructure. Cloud environments use `aws`, `gcp` or `azure` with the appropriate
`--env`; the default profile is `production`. VMware uses local best practices, not an official cloud framework.

Expect explicit findings and unknown evidence: `PASS` exits 0, `FAIL` exits 1, and missing, stale or manual-review
evidence gives `INCOMPLETE` / exit 3 when there are no definite failures. An assessment is not live verification.
It is excluded from `scan all`. The earlier scenario script exercises security scans; architecture has its own
automated tests. See the [Well-Architected guide](../guides/well-architected.md) for MCP, console and skill access.

## Use an agent, MCP or the UI

Follow the same numbered steps and verification/cleanup conditions through your chosen interface. Start with the
[interface setup and coverage guide](interfaces-and-coverage.md); replace account/project/subscription and SSH
placeholders before any live request.

**Agent prompt:** “Run the compliance walkthrough on vmware-lab after listing scanner prerequisites. Separate CIS, Kubernetes, image, host, STIG, FIPS and Well-Architected evidence. Explain missing tools and incomplete reports; do not silently modify infrastructure to make checks pass.”

**MCP starter:** `cloudseed_scan` with:

```json
{
  "cloud": "vmware",
  "env": "lab",
  "kind": "architecture",
  "profile": "lab",
  "json": true
}
```

Use the matching tool for each remaining step in this page; the [command-to-tool map](interfaces-and-coverage.md#command-to-interface-map)
lists the tool family. Keep `vmware-lab` selected. Preview first; add `confirm:true` only to the specific change
you have authorized. Host bootstrap, provider login and interactive applications retain their documented human steps.

**UI:** Select vmware-lab → Resilience → Scans. Run each scanner kind with the framework/host selections from the steps. Architecture uses its own lab/production profile and evidence age; Reports lists saved findings. Tool installation requires the host’s normal authorization.

## Verify it worked

```bash
cs scan reports
ls ~/.cloudseed/envs/vmware-lab/scans/
```

- `scan reports` lists every report with its verdict and counts.
- `scans/` holds `<kind>-<run>.json` and `.md` per scan, the OpenSCAP HTML reports, and the raw tool output in
  `scans/raw/`. Every scan is also in the audit trail.

## Clean up

Scans change nothing on the cluster except their short-lived Jobs. Reports stay until you delete them; `cs undo`
right after a scan removes that scan's own report files.

## What just happened

- Each scanner runs where it has to: kube-bench and kubescape as Jobs in the cluster, trivy against the images,
  OpenSCAP on the hosts over SSH (installed by the `openscap` Ansible role), prowler from your machine.
- Findings are normalised into one report format, which the web console's reports viewer and AI agents read too.
- Learn more: [Security and FIPS](../guides/security-and-fips.md) · [Resilience and scans](../guides/resilience.md) ·
  [Explain index](../reference/explain-index.md)

## Next steps

- [11 · FIPS 140 mode](11-fips-140-mode.md): an environment where `cs scan fips` passes.
- [14 · AI agents](14-ai-agents-and-mcp.md): ask an agent to summarise the failing controls and propose fixes.
- [13 · Day-2 operations](13-day-2-operations.md).
