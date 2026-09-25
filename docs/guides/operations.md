---
title: "Operational readiness"
description: "Health, network diagnostics, deployment profiles, portable specifications, guardrails, upgrades, recovery and acceptance through every cloudseed interface."
---

# Operational readiness

`cs ops` brings environment checks and reviewed changes into one contract shared by CLI, MCP, the console and agents.
Start with `cs ops list --json`: it lists the installed actions, accepted parameters and effects. A local report is
not proof of a live deployment. Reports distinguish **PASS**, **FAIL/BLOCKED** and **INCOMPLETE/UNKNOWN**; exit codes
are 0, 1 and 3 respectively (invalid inputs exit 2).

| Workflow | Actions | What changes |
|---|---|---|
| Health and private networking | `health`, `network` | Local evidence by default; `live` queries resources. `network` with `active` creates a temporary probe workload and cleans it up. |
| Deployment profiles | `profile` | Preview lab/team/production; approval saves desired configuration. Apply remains separate. |
| Portable specification | `spec-export`, `spec-validate`, `spec-diff`, `spec-import` | A versioned document; export to a file and import/save require approval. Neither applies infrastructure. |
| Cost, policy and expiry | `policy-check`, `expiry-plan`, `expiry-cleanup` | Evaluate a supplied plan, enforce saved apply guardrails, or explicitly clean up a saved opted-in expired environment. |
| Drift and upgrades | `drift`, `upgrade-plan`, `upgrade-apply` | Read actual state and plan a pinned upgrade; apply requires approval and repeats readiness checks. |
| Application recovery | `recovery-plan`, `recovery-test` | Restore a selected application into a separate namespace, compare evidence and measure objectives. |
| Sandbox acceptance | `acceptance` | Preview without an account, or explicitly deploy and clean up an isolated cloud test environment. |
| Credential storage | `credentials-backend` | Preview or approve migration between the private file store and the native OS keychain. |

## Choose an interface

```bash
cs ops health aws --env prod --json
cs ops profile aws --env prod --profile production --json
cs ops profile aws --env prod --profile production --approve --json
```

The equivalent MCP tool is `cloudseed_ops_<action>`, replacing hyphens with underscores. Parameters are individual
JSON fields, not a shell string. For example, `cloudseed_ops_profile` takes
`{"cloud":"aws","env":"prod","profile":"production","confirm":true}` to save a reviewed profile. Omit
`confirm` for the preview. The tool schema and CLI use the same operation definition.

Each MCP call has a one-hour default server limit. For a longer maintenance window, configure a bounded limit
of 60–86400 seconds when setting up the server and reconnecting clients. For example, eight hours:

```bash
CLOUDSEED_MCP_TOOL_TIMEOUT=28800 cs setup mcp
CLOUDSEED_MCP_TOOL_TIMEOUT=28800 cs mcp connect codex gemini
```

Setup persists the selected limit in the service and stdio launch environments and writes matching deadlines for
Codex and Gemini. Supply the same value for later setup, reconnect or restart commands; omitting it selects the
one-hour default. Restart/reload clients after changing their configuration. Other clients require their own matching
deadline; for Claude Code, start it with `MCP_TOOL_TIMEOUT=28800000` (milliseconds) for the eight-hour example.
Operation `timeout_s` values bound individual stages and do not extend the total MCP deadline. If a call times out
or is cancelled, inspect cluster/provider status and operation artifacts before retrying: a remote upgrade, backup
or restore can continue after the local process is interrupted, and cleanup may need manual review.

MCP also bounds inputs and resources: HTTP/stdio requests are limited to 16 MiB, batches to 32 entries and 16 MiB
of replies, individual regular resource files to 256 KiB, and environment listings to 200 entries/2 MiB
with at most 64 nested JSON levels. Oversized or unsupported resource reads fail clearly; split broad requests into smaller reads when a limit is reached.

In the console, select the environment, open **All actions → Operations & readiness**, choose the action and fill
its named fields. Object inputs such as spec or Terraform plan accept JSON. Environment and cloud are separate fields. Actions that change resources or save configuration
require the confirmation control. Follow the job in **Activity**, then inspect its output and **Reports → operations**.
Resilience shortcuts lead to the same actions.

For an agent, say: “Inspect aws-prod with health, network and architecture reports. Explain unknown evidence. Preview
production settings and cost differences; save or deploy only within the changes I approve.” Install/update bundled
skills with `cs skill install` before starting the agent. A skill supplies instructions; it does not grant cloud
credentials, turn an incomplete assessment into a pass, or bypass operation approval.

## Deployment profiles and costs

| Setting | Lab | Team | Production |
|---|---|---|---|
| Private Kubernetes API | Enabled | Enabled | Enabled |
| AWS | 2 AZs, shared NAT, 1 node | 2 AZs, shared NAT, 2 nodes | 3 AZs, NAT per AZ, 3 nodes |
| GCP | Zonal, 1 node | Zonal, 2 nodes | Regional control plane, 3 explicit node zones, 1 initial node per zone |
| Azure | Free tier, 1 node | Standard tier, 2 nodes | Standard tier, 3 node zones, 3 nodes |
| VMware | 1 control plane, 1 worker | 1 control plane, 2 workers | 3 control planes, 3 workers on the same physical host |
| Desired backup retention | 168 hours | 720 hours | 2160 hours |

Profiles enable Kubernetes and save real supported topology settings. They can increase cost or cause replacement
when applied to an existing cluster. Review the Terraform plan and recovery path first. GKE node count/min/max are
**per zone**. Zone availability, quotas and Azure VM-size support still require provider validation. Multiple VMware
control planes on one workstation do not survive failure of that workstation.

Backup schedule/retention and the specification's platform list are **desired intent**. Run `cs dr schedule` and
`cs platform install` to make them live; saving the document does not install or enforce workload policy. Production
also requests longer logs and GCP Data Access audit collection where the baseline is owned by this environment.

Cost previews price known components and list omissions. Regional pricing, discounts, traffic, actual logs, backups,
application usage, autoscaling and the AKS Standard control-plane fee are not completely priced. A budget is a
planning guard, not a billing cap. With a saved budget, incomplete coverage blocks apply by default. Setting
`require_complete_cost: false` accepts that uncertainty explicitly; a known estimate already above budget still blocks.

## The portable document

```yaml
schema_version: 1
cloud: aws
environment: prod
configuration:
  name: cloudseed
  region: us-east-1
  network_cidr: 10.40.0.0/16
  allowed_ssh_cidrs:
    - 203.0.113.7/32
  tags:
    team: platform
  vars:
    enable_kubernetes: true
    az_count: 3
    single_nat_gateway: false
  extra_vars:
    kubernetes_node_min: 3
    kubernetes_node_max: 6
operations:
  profile: production
  block_destroy: true
  budget_max_monthly: 500
  require_complete_cost: true
  backup:
    schedule: '0 2 * * *'
    ttl: 2160h
    namespaces: ["shop"]
  platform: ["velero", "kyverno"]
```

Use your actual SSH source, target region and reviewed budget. This example is a schema illustration, not a complete
production architecture or a cost quote. Credentials, SSH keys, Terraform state/backend credentials, local paths and
resource ownership IDs are excluded. Import retains the current environment's identity and machine-specific keys.
To copy intent to another environment, explicitly change the document's `environment` and review its scope.

```bash
cs ops spec-export aws --env prod --output cloudseed.yaml --approve --json
cs ops spec-validate --input cloudseed.yaml --json
cs ops spec-diff aws --env prod --input cloudseed.yaml --json
cs ops spec-import aws --env prod --input cloudseed.yaml --approve --json
cs plan aws --env prod
```

Export writes JSON, which is valid YAML 1.2. The dependency-free reader also accepts indented YAML mappings, scalar
lists, JSON flow containers and quoted/plain scalar values. It rejects tags, anchors, aliases, duplicate keys,
multiple documents, block strings and inputs above 512 KiB. Use JSON syntax inside inline lists/maps.

Saved operations policy lives in `config.json` under `operations`. `policy-check` accepts a Terraform `show -json`
plan object without copying resource values into the report. Apply gates evaluate the actual saved plan, including
replacement/deletion actions. Expiry never creates a background timer: `expiry-cleanup` requires a saved elapsed
`expires_at`, saved `cleanup_opt_in: true`, and explicit approval. Cleanup retains configuration and state storage.

## Follow a complete walkthrough

- [16 · Health and private networking](../scenarios/16-health-and-network.md)
- [17 · Profiles, specs and guardrails](../scenarios/17-profiles-specs-and-guardrails.md)
- [18 · Drift, upgrades and application recovery](../scenarios/18-upgrades-and-recovery.md)
- [19 · Acceptance and trusted releases](../scenarios/19-acceptance-and-releases.md)
- [All interfaces and feature coverage](../scenarios/interfaces-and-coverage.md)
