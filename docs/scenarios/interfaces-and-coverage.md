---
title: "Scenario interfaces and feature coverage"
description: "Concrete CLI, agent, MCP and console routes for every scenario, with explicit bootstrap requirements and catalog coverage rather than claims of unexecuted live tests."
---

# Scenario interfaces and feature coverage

Each numbered walkthrough has its CLI commands, an agent prompt, a concrete MCP starter call and console directions.
Use the same selected cloud/environment, inputs, expected results and cleanup steps in every interface. Reports and
side effects come from the same implementation; choosing an agent does not make a cloud deployment credential-free.

The [generated command matrix](index.md#command-coverage-matrix) maps every CLI command/subcommand to a walkthrough.
The [checked interface examples](interface-examples.json) and [coverage manifest](feature-coverage.json) bind those
walkthroughs to real MCP schemas and catalog items. They describe documented coverage, not a claim that all charts
or all cloud deployments have been run live.

## One-time setup

The human installs Cloudseed and any required runtime, logs in to the provider, authorizes OS keychain access where
applicable, and starts the interface. These are authentication or host-control steps rather than actions an already
connected MCP server can use to create its own connection.

```bash
cs doctor aws
cs skill install
cs enable agentic
cs setup mcp
cs enable ui
```

Select your agent/model and connect the MCP client as shown in [14](14-ai-agents-and-mcp.md). Open the console as
shown in [15](15-web-console-and-finops.md). Enter secrets into the provider login or Credentials form, not chat or
operation parameters. Interactive SSH, k9s, browser authentication and desktop VPN prompts may still require a human;
noninteractive checks and infrastructure steps have tool/form routes.

## Command-to-interface map

For MCP, read the named tool's schema (`cs mcp tools`). A CLI subcommand usually becomes an `action` field; `scan`
uses `kind`, managed platforms use `service` plus `args`, and every new operation has its own generated tool. Pass
cloud and environment explicitly for changes. `confirm:true` approves the named change, not future unrelated changes.

| CLI family | MCP tool | Console route |
|---|---|---|
| `setup`, `plan`, `apply`, `destroy` | `cloudseed_setup`, `cloudseed_plan`, `cloudseed_apply`, `cloudseed_destroy` | Create; selected Environment actions |
| `list`, `status`, `output`, `inventory`, `troubleshoot`, `doctor` | matching `cloudseed_<command>` | Overview, Environments, All actions |
| `update-ip`, `provision`, noninteractive `ssh` | `cloudseed_update_ip`, `cloudseed_provision`, `cloudseed_ssh` | Selected Environment / All actions |
| `k8s`, `env`, `node` | `cloudseed_k8s`, `cloudseed_env`, `cloudseed_node` | Environment Kubernetes/Nodes; current environment selector |
| `kubectl`, `helm` | `cloudseed_kubectl`, `cloudseed_helm` | All actions; explicit argument list |
| `platform` | `cloudseed_platform` | Platform catalog, plan/install/uninstall/status/UI actions |
| `vpn` | `cloudseed_vpn` | Environment VPN actions; host prompts may still be required |
| `finops` | `cloudseed_finops` | All actions → FinOps; Reports |
| `dr`, `chaos`, `scan` | `cloudseed_dr`, `cloudseed_chaos`, `cloudseed_scan` | Resilience; Reports |
| `databricks`, `snowflake` | `cloudseed_managed` | All actions → managed platform forms |
| `undo`, `explain`, `help`, `skill show` | `cloudseed_undo`, `cloudseed_explain`, `cloudseed_help`, `cloudseed_skill` | All actions / Help / context explain buttons |
| `ops ACTION` | `cloudseed_ops_ACTION` (hyphens become underscores) | All actions → Operations & readiness; Resilience shortcuts |
| Agent/model/service setup, credentials entry, installations | Human host setup; read-only status remains available | Agents & MCP, Credentials, Help; native authentication/installation when requested |
| Interactive `ssh` / `k9s` | Use noninteractive SSH or kubectl checks; interactive session remains human | Use terminal for the interactive application |

An agent with the bundled skills uses these same operations or their CLI equivalents. Ask for the scenario number,
selected environment and exact scope. If the agent cannot authenticate or a prerequisite is missing, complete that
step and resume; do not ask it to read credential files or weaken the guard to get a passing result.

## Catalog coverage

The catalog contains optional and provider-specific items. A group walkthrough teaches the inspect → plan → install
→ verify → uninstall loop; it does not ask you to install every heavyweight item simultaneously. For **each item**
in the manifest, substitute its name in that loop, review `only`, requirements and notes via `platform info`, and
provide the resources/credentials it needs. The dependency plan is authoritative.

```bash
cs platform info minio
cs platform plan minio vmware --env lab
cs platform install minio vmware --env lab
cs platform status vmware --env lab
cs platform uninstall minio vmware --env lab
```

MCP performs the same loop with `cloudseed_platform`, `items:["minio"]`, explicit `cloud`/`env`, and
`action:"info"|"plan"|"install"|"status"|"uninstall"`; mutation calls need `confirm:true`. In the UI select the same
item in **Platform**, inspect its details, Plan, then Install or Uninstall and check Activity. An agent can follow
this loop for a specific item or group; it should retain the item-specific notes and verification checks.

| Catalog group | Walkthrough | Additional validation |
|---|---|---|
| `basek8s`, `scaling` | [06](06-platform-in-one-command.md), [13](13-day-2-operations.md) | Private service access, metrics and node/autoscaler behavior |
| `data`, `ai`, `agentic` | [07](07-data-and-ai-stack.md) | Storage, database/model readiness and application-specific checks |
| `finops` | [15](15-web-console-and-finops.md) | OpenCost data requires a running cluster and metrics |
| `devsecops`, `security` | [06](06-platform-in-one-command.md), [10](10-compliance-scans.md) | Token prerequisites, policy audit results and affected-workload review |
| `resilience` | [08](08-backups-you-can-trust.md), [18](18-upgrades-and-recovery.md) | Completed backups/restores, volume evidence and recovery objectives |
| `chaos` | [09](09-chaos-engineering.md) | Explicit experiment target, recovery and cleanup |

## What is tested

Documentation tests parse the CLI examples, validate each checked MCP starter against its schema, require agent/UI
instructions on every page, and compare the feature manifest with the current command registry, operations and
platform catalog. The executable scenario scripts test local/fixture behavior and clearly skip unavailable live
steps. Provider mock tests validate real Terraform schemas without cloud calls. Container and standalone-binary
pipelines test their own runtime packaging.

Cloud acceptance is a separate opt-in activity in [19](19-acceptance-and-releases.md). Without sandbox credentials,
a report must say that provisioning, egress, chart readiness, upgrade and recovery were not verified in a live cloud.
