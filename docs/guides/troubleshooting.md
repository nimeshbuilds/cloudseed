---
title: "Troubleshooting cloudseed - deterministic diagnosis and common fixes"
description: "Diagnose a failed cloudseed run with cs troubleshoot, find the logs, and fix common problems with credentials, SSH, Terraform and VMware."
---

# Troubleshooting

When something fails, cloudseed already has most of the answer on disk. Start with one command.

## Step 1: let cloudseed diagnose it

```bash
cs troubleshoot aws --env dev --log
```

No agent is involved: it reads what cloudseed always records and checks the live environment.

- **Recent runs** from the audit log, with exit codes and durations.
- **The failed change.** A failed `setup`, `apply`, `destroy` or `install` is diagnosed before read-only runs that
  failed after it, and its log is matched against known failure signatures, each with a fix.
- **Live checks:** tools and versions, credentials, whether the bastion answers on port 22, whether your current public
  IP is still allowed, SSH key presence, provisioning status, VMware host, provider and vmrest state, images, and disk
  space. An unreadable local state is reported too.
- **Findings**, each with the command that fixes it.

`--log` also prints the tail of the last failure's log; `--last N` shows more recent runs (default 10).

## Step 2: check tools and credentials

```bash
cs doctor aws
```

`doctor` shows every tool with its version and whether credentials were detected; with a cloud it checks them live
and ends with one verdict line naming what keeps that cloud from working.

## Common problems

| Symptom | Fix |
|---|---|
| "terraform is not installed" | `cs install terraform`, or run in the container: `cs --runtime container ...` |
| No credentials detected | run the login command `doctor` prints (`aws configure`, `gcloud auth application-default login`, `az login`), or store keys with `cs creds set` |
| SSH to the bastion times out | your public IP changed: `cs update-ip <cloud> --env <name>` |
| A plan is shown and nothing is applied (exit 3) | that is the approval gate: add `--auto-approve` (a plan with no changes exits 0) |
| A `-y` run stops with exit 2 about a missing tool | install it first (`cs install <tool>`) or set `CLOUDSEED_AUTO_INSTALL=1` |
| "already exists" errors | cloudseed adopts a resource only when its tags say it belongs to this environment (it asks when the owner cannot be read; `CLOUDSEED_ADOPT=1` without a terminal). Anything else is refused: rename or remove it. `cs explain reconcile` |
| GuardDuty or Security Hub already enabled (AWS) | they are never adopted: `--var enable_guardduty=false` / `--var enable_security_hub=false`; an existing account analyzer: `--var enable_access_analyzer=false` |
| Second environment in the same AWS account | `--var enable_account_baseline=false` (same region); alone in another region, also `--var enable_regional_baseline=true` |
| Azure: permission error on the activity log | `--var enable_activity_log=false` (it needs Contributor at subscription scope) |
| Azure: 403 on role assignments (AKS, Velero) | Owner, or Contributor + User Access Administrator |
| Provider checksum or "plugin failed to start" errors | another Terraform run shares the provider cache (`TF_PLUGIN_CACHE_DIR`): let it finish and re-run, or give each parallel run its own cache (VMware environments never use the cache: their provider is built on your machine). Otherwise delete that root's `.terraform.lock.hcl` and `.terraform` and re-run |
| "unknown command" for a sentence | natural language goes through the agent: `cs agentic "<sentence>"` |
| "Unexpected error" | the redacted traceback is in the environment's log, or `~/.cloudseed/logs/<ts>-<cmd>-crash.log`; `CLOUDSEED_DEBUG=1` prints it |
| A script or CI job must never prompt | `-y` on every command, or `CLOUDSEED_NONINTERACTIVE=1` |

### VMware

| Symptom | Fix |
|---|---|
| VMware is not installed | `setup vmware` offers to install it; or `cs install vmrun` (Broadcom requires a login to download: cloudseed opens the page and waits for the installer in `~/Downloads`) |
| A second lab is refused while another has VMs | every lab without `--cidr` shares VMware's host-only vmnet. Destroy the other one, or give this one its own network: run `sudo vmrest`, export `VMREST_USER` / `VMREST_PASSWORD`, and pass `--cidr` with a private range |
| An item is skipped on Apple silicon | it is published for amd64 only (harbor, litmus, gitlab, kubeflow-pipelines, vllm-stack); `--force` tries anyway |
| Not enough memory for Kubernetes | `--var kubernetes_workers=0` runs workloads on the control plane; smaller nodes: `--var kubernetes_memory_mb=...` |
| The provider source changed | `cs install vmware-provider --rebuild` |
| "Could not read the Terraform outputs" right after `Apply complete!` | the VMs exist; terraform itself failed to read them back (its error is shown under the warning, for example a provider checksum that no longer matches). Fix that, then `cs provision vmware --env <name>` re-reads the outputs and provisions the bastion |

### Kubernetes and the platform

| Symptom | Fix |
|---|---|
| `cs kubectl` cannot reach a private endpoint | it tunnels through the bastion on demand; check `cs troubleshoot`, or connect the [VPN](vpn.md) |
| GKE: kubectl authentication fails | install `gke-gcloud-auth-plugin` (`cs install gke-gcloud-auth-plugin`) |
| `platform install` exits 1 | every named item was skipped for a reason (missing token, conflict, architecture, FIPS): `cs platform plan <items>` shows why |
| kagent or the GitLab runner is skipped | set its token: `cs creds set ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`), `cs creds set GITLAB_RUNNER_TOKEN` |

## Where the logs are

| What | Where |
|---|---|
| One environment's runs | `<workdir>/logs/audit.jsonl` and `<workdir>/logs/<timestamp>-<command>.log` (default workdir `~/.cloudseed/envs/<cloud>-<env>`) |
| Every run | `~/.cloudseed/logs/audit.jsonl` |
| Crashes | `~/.cloudseed/logs/<ts>-<cmd>-crash.log` |
| Web console / MCP server | `cs ui logs`, `cs mcp logs` |
| A purged environment | `~/.cloudseed/logs/purged/<cloud>-<env>/` |

Logs are redacted: keys, tokens and passwords are masked before they are written.

## Still stuck?

- `cs explain <feature>` shows how the part that failed is built, and `cs help <command>` every flag.
- Revert the last change: `cs undo --list`, then `cs undo <cloud> --env <name>`.
- Open an issue on [GitHub](https://github.com/nimeshbuilds/cloudseed/issues) with the output of
  `cs troubleshoot <cloud> --env <name> --log` and `cs doctor`. Both are redacted, but read them before you paste.
