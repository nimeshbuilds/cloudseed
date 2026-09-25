---
title: "Well-Architected assessments"
description: "Assess saved Cloudseed configuration and evidence across AWS, Google Cloud, Azure and VMware, through the CLI, MCP, console and agent skills."
---

# Well-Architected assessments

`cs scan architecture` assesses an existing environment's saved configuration and local evidence. It shows
findings, the evidence behind them and remediation, organised by architectural pillar. The same assessment is
available in the CLI, MCP, local console and bundled agent skills.

The scanner queries no cloud APIs, provisions nothing and installs no tools. It saves JSON and Markdown reports.
Saved configuration describes intended settings; it does not prove that deployed resources still match them.
This is a scoped technical assessment, not provider certification or a complete organisational review.

## Run an assessment

```bash
cs scan architecture aws --env prod --profile production --max-age-days 30
cs scan architecture gcp --env prod --json
cs scan architecture azure --env prod --json
cs scan architecture vmware --env lab --profile lab --json
```

Choose an existing environment. Target selection follows the [CLI environment rules](cli.md); provide the target
and `--env` explicitly when several environments exist. No cloud credentials are needed for this local assessment.

| Option | Meaning |
|---|---|
| `--profile production` | Default assessment policy, including production availability expectations. |
| `--profile lab` | Relax production availability expectations for a lab; missing evidence still remains unknown. |
| `--max-age-days 30` | Maximum age of saved evidence; 1–3650 days, default 30. |
| `--json` | Print the assessment as structured JSON for scripts and agents. |

These are **assessment profiles**, not deployment presets. Selecting one never changes the environment.
`cs scan all` continues to run the security suite; run `cs scan architecture` explicitly.

## Interpret the result

| Verdict | Exit code | Meaning |
|---|---|---|
| `PASS` | `0` | The applicable assessed checks passed. Coverage and evidence limits still apply. |
| `FAIL` | `1` | At least one definite finding needs attention. Other checks may also lack evidence. |
| `INCOMPLETE` | `3` | No definite failure was found, but evidence is missing, stale or needs manual review. |
| Invalid arguments | `2` | Correct the command input before retrying. |

Failure takes precedence over incomplete evidence. Do not treat exit 3 as success or use a security scanner's
`PASS` as proof of overall architectural readiness. A manual review requirement remains visible even when all
automated configuration checks pass. Review each finding's evidence and suggested remediation before applying changes.

The initial rule set retains manual review items as `UNKNOWN` and does not accept manual attestations. Consequently,
an assessment with no definite failures is `INCOMPLETE`; individual configuration or recovery checks can still pass.

Reports are saved in the environment's `<workdir>/scans/architecture-<run>.json` and `.md`, alongside security scan
reports. Use `cs scan reports` or the console's **Reports** view to find them. Re-run the assessment after changing
configuration or collecting evidence; it does not silently refresh evidence with live scans or recovery drills.

## What the scanner checks

| Input | Checks and limits |
|---|---|
| Saved configuration | SSH source ranges, Kubernetes API exposure and provider logging settings. A pass describes declared intent. |
| Provider topology | AWS zones and NAT layout; current zonal GKE design; AKS tier/zone limitations; VMware's single physical host. Production expectations are explicit. |
| Latest cloud security report | Freshness and failed checks. Even a security `PASS` cannot prove complete coverage or permissions. |
| Latest Kubernetes DR drill | A complete, recent sample restore with verified volume contents. It does not establish application recovery targets. |
| Inventory installation notes | Whether Vault or Kyverno policies were recently installed. Effective values and overrides remain unknown. |
| Manual review | Baseline ownership, alerts, recovery objectives, drift/upgrades, performance, cost allocation/budgets and sustainability remain unknown. |

Only the newest saved report is considered, so an older success cannot conceal a newer failure or unreadable report.
Missing, stale, future-dated or unreadable evidence remains unknown. Evidence is bounded and local; reports are not
independently authenticated attestations. The scanner does not read Terraform state or credentials.

## Provider guidance

Cloudseed maps its checks to each provider's guidance rather than inventing one certification score:

| Target | Assessment mapping |
|---|---|
| AWS | Operational excellence, security, reliability, performance efficiency, cost optimization and sustainability. |
| Google Cloud | Operational excellence, security/privacy/compliance, reliability, performance optimization, cost optimization and sustainability. |
| Azure | Reliability, security, cost optimization, operational excellence and performance efficiency. Sustainability is separate additional guidance. |
| VMware | Local infrastructure best practices. This is not an official cloud Well-Architected framework. |

The framework structures come from the [AWS pillars](https://docs.aws.amazon.com/wellarchitected/latest/framework/the-pillars-of-the-framework.html),
[Google Cloud Well-Architected Framework](https://docs.cloud.google.com/architecture/framework) and
[Azure pillars](https://learn.microsoft.com/en-us/azure/well-architected/pillars).
An assessment covers the checks Cloudseed can support with available configuration and saved evidence. Workload
requirements, acceptable risk, recovery objectives and operational ownership still need a human review.

## Use every interface

**CLI:** run the commands above. `cs help scan` documents the flags, and `cs explain architecture --json` explains
the implementation and evidence limits.

**MCP:** call the existing `cloudseed_scan` tool. The architecture kind needs no `confirm=true`:

```json
{
  "kind": "architecture",
  "cloud": "aws",
  "env": "prod",
  "profile": "production",
  "max_age_days": 30,
  "json": true
}
```

**Web console:** select the environment, open **Resilience**, choose the architecture assessment, and select its
profile and evidence age. Output streams through the normal job drawer; the saved report appears in **Reports**.

**Skills and agents:** `cs skill show architecture` gives the operating guide. The core, cloud and platform skills
also advertise the scanner. Built-in and external agents use the same CLI, and MCP clients can read the skill at
`cloudseed://skills/cloudseed-architecture`. Example task: “Assess the AWS prod environment against Well-Architected
guidance and explain failures and unknown evidence.”

## Next steps

Use the findings to choose the next action; the assessment itself makes no repairs. Security evidence comes from
the [security scanners](security-and-fips.md), recovery evidence from [DR drills](resilience.md), and cost evidence
from [FinOps reports](finops.md). Live scans and drills have their own prerequisites and effects: a drill can change
workloads, and collecting evidence should be an explicit follow-up action.
