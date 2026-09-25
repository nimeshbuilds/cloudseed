---
name: cloudseed
description: Drive the cloudseed CLI to create, inspect, change or tear down secure cloud landing zones (VPC/VNet, public+private subnets, NAT, hardened bastion reachable only from the user's IP, security baseline) on AWS, GCP or Azure - or local VMware VMs - with Terraform. Use whenever the user mentions cloudseed, "set up aws/gcp/azure", bastion, landing zone, or asks to destroy cloud infrastructure managed by cloudseed.
---

# cloudseed

cloudseed is a deterministic CLI wrapping Terraform. **Always act through `cloudseed` commands** — never run
`terraform` directly, never edit files under `~/.cloudseed`, never read or print state files, credential
files or environment variables. Output you see from `cloudseed` is already redacted; do not try to recover
secrets.

`cs` is a short alias for `cloudseed`. `cloudseed agentic "..."` is how a human hands a task to an agent; you never
call it yourself.

## Mental model

- One **environment** = `<cloud>-<env>` (e.g. `aws-dev`). Config lives in `~/.cloudseed/envs/<cloud>-<env>/config.json`.
- `setup` is idempotent: re-running it with new flags updates the environment (plan is shown before apply).
- Terraform state is `remote` (hardened bucket cloudseed bootstraps) or `local`.
- Every resource is prefixed `<name>-<env>` and tagged `Project=<name>`, `Environment=<env>`, `ManagedBy=cloudseed`,
  `Owner`, `CloudseedEnv`, `CloudseedEnvId` (reconcile adopts an existing resource only when these tags say it is this
  environment's; `--tag` cannot set `ManagedBy`, `CloudseedEnv` or `CloudseedEnvId`, `--tag KEY=` removes a saved
  tag, and tag keys are case-insensitive).
- `status`, `output`, `inventory`, `troubleshoot`, `plan`, `ssh`, `k8s` and `vpn` may leave out `<cloud>`: they act on the
  environment named by `--env`, else the current one (`cloudseed env use`), else the only one. `--env` also takes the
  id `cloudseed list` shows (`--env aws-prod`). `<cloud>` without `--env` means that cloud's only environment; with
  several, read-only commands (status, output, inventory, troubleshoot, plan, ssh, k8s, vpn, finops, scan) use the
  current one; otherwise `dev` is used when it exists (for a command that changes things, only when no other
  environment is current), else the command stops with the list (exit 2). So always pass `<cloud> --env <name>`
  when several environments exist.

## Commands

| Goal | Command |
|---|---|
| Create/update an env | `cloudseed setup <aws\|gcp\|azure\|vmware> --env dev [--name X] [--region R] [--state remote\|local] [--cidr 10.0.0.0/16] [--allow-ip IP] [--var key=value] -y --auto-approve` |
| Preview changes | `cloudseed plan <cloud> --env dev` |
| Re-apply saved config | `cloudseed apply <cloud> --env dev --auto-approve` |
| Inspect | `cloudseed status <cloud> --env dev`, `cloudseed output <cloud> --env dev --json`, `cloudseed list` |
| Change allowed SSH IP | `cloudseed update-ip <cloud> --env dev [--allow-ip 1.2.3.4] --auto-approve` (cloud targets only; IPv4, nothing wider than a /8 and at most two /8s; a range as its network - `203.0.113.0/24`, never `203.0.113.7/24`; applies only the SSH-source change) |
| SSH to bastion | `cloudseed ssh <cloud> --env dev` (an interactive session: human-only - give the user the command) |
| Destroy some things | `cloudseed destroy <cloud> --env dev --target module.stack.module.bastion --auto-approve` |
| Destroy everything | `cloudseed destroy <cloud> --env dev --auto-approve [--purge-state] [--purge]` |
| Local VMs (VMware) | `cloudseed setup vmware --env lab [--var workload_count=2] [--var enable_kubernetes=true]` (see cloudseed-vmware skill) |
| Current cluster | `cloudseed env`, `cloudseed env use <cloud>-<env>` (or a name only one environment has; cluster commands act on it), `cloudseed env clear` |
| Scale nodes | `cloudseed node add [--count N] [--role worker\|control-plane]`, `node list`, `node remove <name>`, `node scale <cloud> --env dev --count N [--min N] [--max N]` (EKS/GKE/AKS; see cloudseed-platform skill) |
| Platform catalog | `cloudseed platform list\|info\|plan\|install\|uninstall\|status <group\|item ...>` groups: basek8s scaling data ai agentic finops devsecops security resilience chaos (see cloudseed-platform skill) |
| Cluster tools | `cloudseed kubectl ...`, `cloudseed helm ...` (per-env kubeconfig, bastion tunnel when private; in an agent session the output is redacted and `kubectl edit` / `exec -it` are refused); `cloudseed k9s` is a full-screen UI: human-only - give the user the command |
| Managed data platforms | `cloudseed databricks connect host=...\|test\|<args>`, `cloudseed snowflake connect account=... user=...\|test\|<args>` (see cloudseed-managed skill) |
| Diagnose | `cloudseed troubleshoot <cloud> --env dev [--log]`, `cloudseed inventory <cloud> --env dev` |
| How something works | `cloudseed explain <thing> --json` - a feature, target, command, topic, platform group or item, or `variable <cloud> <name>` (read-only; see below) |
| What is installed | `cloudseed install list`, `cloudseed doctor [cloud]` (read-only; `doctor <cloud>` exits 1 with an "is not ready" verdict when a required tool or the credentials are missing) |
| Install software | Human-only: give the user `cloudseed install <tool\|group\|skills\|agent\|vmrun\|vmware-provider\|image\|bundle>` (or `cloudseed deps install <tool>`) and let them run it; never run it yourself |
| Agents | `cloudseed agents`, `cloudseed skill list\|show`, `cloudseed model` (shows the models), `cloudseed use list` (read-only). Human-only - give the user the command: `cloudseed use <agent>`, `cloudseed model <id>`, `cloudseed enable\|disable agentic\|headliner`, `cloudseed skill install` |
| Disaster recovery | `cloudseed dr status\|backups\|backup [name]\|restore <backup>\|schedule <name> --cron "0 2 * * *"\|test\|describe\|logs backup\|restore <name> [--cloud <cloud>] [--env dev]` (Velero; cron in UTC; `cs platform install velero` creates the bucket + identity in the cloud first) |
| Chaos engineering | `cloudseed chaos run [basic\|network\|stress\|full\|<experiment>...] [--target ns/deploy] [--cloud <cloud>] [--env dev]`, `cloudseed chaos list\|status\|stop\|report` (PASS/FAIL report per experiment) |
| Security scans | `cloudseed scan cis\|kube\|images\|host\|stig\|cloud\|fips\|all [<cloud> --env dev]`, `cloudseed scan reports` (kube-bench, kubescape, trivy, OpenSCAP CIS/STIG, prowler, FIPS verifier) |
| FIPS mode | `cloudseed setup <cloud> --env dev --var fips_mode=true` (new envs only; RSA-4096 SSH keys; VMware, and AWS with a VPN host, need `UBUNTU_PRO_TOKEN`; kubeadm/tailscale/ed25519 refused), verify with `cloudseed scan fips` |
| Undo | `cloudseed undo [<cloud> --env dev] [--auto-approve]`, `cloudseed undo --list`, `cloudseed undo --id ID` (that entry, once it is the newest of its environment), `cloudseed undo --id ID --drop` (discard a step that can never succeed). Fifteen undo points per env (at most five of one kind; reports and scans have five more of their own); after that destroy and start over. Global entries (settings, agents, MCP, UI, credentials: `cloudseed undo --global`) are the user's only - you cannot undo them |
| Web console | `cloudseed ui status\|logs` (read-only). Human-only - give the user the command: `cloudseed enable ui` (local, token-protected console with every action as a button), `cloudseed ui [open\|start\|stop\|restart\|token]`, `cloudseed disable ui` |
| Credentials vault | `cloudseed creds list\|set KEY\|unset KEY\|clear` (local 0600 vault injected into every command; you never read it). Human-only: tell the user to run `cloudseed creds set KEY` themselves (hidden prompt, needs a terminal); `unset`/`clear --forget` keep no copy for undo |
| MCP server | `cloudseed mcp status\|guide\|tools\|config\|test\|logs` (read-only). Human-only - give the user the command: `cloudseed setup mcp [--client all\|none\|<name>...] [--transport http\|stdio]` deploys the local server + connects clients + prints the guide; `cloudseed mcp connect\|disconnect\|start\|stop\|restart\|token\|serve`; `cloudseed destroy mcp` removes it (`cloudseed enable\|disable mcp` toggles it) |
| Check tools/creds | `cloudseed doctor [cloud]` (a missing tool: give the user `cloudseed install <tool>`) |
| Something failed | `cloudseed troubleshoot <cloud> --env dev --log` (audit log + the failed change + live checks), `cloudseed inventory <cloud> --env dev` |
| Harden / re-provision hosts | `cloudseed provision <cloud> --env dev [--host bastion\|vpn\|k8s]` (runs automatically after setup) |
| Kubernetes | `cloudseed setup <cloud> --env dev --var enable_kubernetes=true`, then `cloudseed k8s info\|kubeconfig\|tunnel\|untunnel <cloud> --env dev` (`kubeconfig` merges the cluster into the user's kubeconfig and makes it the current kubectl context - say so; `cloudseed undo` switches back) |
| VPN | `cloudseed setup <cloud> --env dev --var enable_vpn=true`, then `cloudseed vpn add-user <cloud> --env dev <user>`, `cloudseed vpn connect\|status <cloud> --env dev` |

Non-interactive execution: always pass `-y` (never prompt) BEFORE the command - `cloudseed -y setup aws ...` - (after
a pass-through command such as `kubectl`, `helm`, `ssh`, `databricks` it would be handed to that tool) and, when the
user has approved the change, `--auto-approve`. Without `--auto-approve` the command stops after the plan (exit code
3; a plan with no changes exits 0) — use that to show the user what will happen first; `destroy` does the same when
only leftovers (VM files, the state storage, the working directory) remain. In the built-in agent that preview runs
unasked and the `--auto-approve` call is the one the user approves. `setup --name` on a deployed environment replaces
most of its resources and is refused unattended: run it with `--plan-only`, show the plan, then `cloudseed apply`. A
first `setup --plan-only` with remote state plans the state storage and the stack and creates nothing. With `-y` a
missing tool is not installed: the command stops with exit code 2 and the `cloudseed install <tool>` command for the
user.

Cloud-specific required inputs: GCP needs `--project-id`; Azure needs `--subscription-id` (both may come
from env vars). AWS optionally takes `--profile`.

Any stack variable except those cloudseed sets itself can be overridden with `--var name=value`, read by the variable's
declared type (text stays text, e.g. `--var kubernetes_version=1.30`; numbers, `true`/`false` and JSON lists/maps are
decoded, e.g. `--var az_count=3 --var single_nat_gateway=false`; `--var name=null` drops a saved override); the same flag
answers setup questions (`--var guest_os=debian-12`). Unknown names are refused with a did-you-mean. Setup refuses
`name`, `environment`, `region`/`location`, the network CIDR, `allowed_ssh_cidrs`, `ssh_public_key`, `tags`/`labels`,
`platform_prereqs` (vmware: `base_disk`, `guest_os_id`) and names the flag to use (`--name`, `--env`, `--region`,
`--cidr`, `--allow-ip`, `--ssh-public-key`, `--tag`, `platform install`, `--var guest_os`). See the per-cloud skills for
the important variables, and `cloudseed help variables <cloud>` / `cloudseed help outputs <cloud>` for the complete,
generated lists.

## Look it up before guessing

When you are unsure what a feature, command, flag, platform item or setup variable does (what `single_nat_gateway`
changes, what `platform install security` brings, what `destroy --purge` removes, which `--var` sets a question), look
it up instead of guessing: `cloudseed explain <thing> --json` returns the page as data - `kind`, `title`, `summary`,
`sections` (what it builds, files, controls, defaults, where state lives), `commands` and `also`. A word that names
several things resolves feature > target > platform group/item > command/topic; pick one with
`feature|target|topic|command|group|item <name>`, and `variable <cloud> <name>` (or `<cloud> <name>`) is one setup
setting with its default and the question that asks for it. When `found` is false (exit 1), retry with one of
`did_you_mean`; `cloudseed explain --json` with no argument is the index of everything explainable. Over MCP the same
data is `cloudseed_explain` with `format=json` or the resource `cloudseed://explain/<query>` (e.g.
`cloudseed://explain/variable/aws/single_nat_gateway`). The user sees the same page behind the "?" buttons of the web
console, so quote it when you explain something to them.

## Workflow

1. Run `cloudseed list` and `cloudseed doctor <cloud>` to learn what exists and whether credentials are present.
   If credentials are missing, tell the user the login command printed by doctor — do not attempt to obtain credentials yourself.
2. For changes, run the command **without** `--auto-approve` first, summarize the plan for the user, then re-run with `--auto-approve` once they agree (or when they already asked for it explicitly).
3. After apply, report the outputs that matter: bastion IP, subnet IDs, security-group / tag names for workloads, and the SSH command.
4. When the user wants to revert what was just done, prefer `cloudseed undo --list` then `cloudseed undo <cloud> --env <name>` over ad-hoc reverse commands.
5. Destroy is irreversible: restate exactly what is being destroyed. Prefer `--target`/`--select` for partial teardown. Only add `--purge-state`/`--purge` when the user asked for a clean slate.

## Safety rules

- Never open the bastion to `0.0.0.0/0` (the CLI refuses anyway).
- Never disable the security baseline or flow logs unless the user explicitly asks and understands the impact.
- Never print, cat, or search credential files (`~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.ssh`, `~/.kube`,
  `~/.docker/config.json`), `*.tfstate*`, or cloudseed's secret files: the vault `~/.cloudseed/credentials.json`,
  `~/.cloudseed/gcp-credentials.json`, the data-platform connections (`~/.cloudseed/managed.json`,
  `~/.cloudseed/managed/`), the vmrest login `~/.cloudseed/vmware.json`, Helm registry logins (`~/.cloudseed/helm/`),
  the MCP and UI tokens (`~/.cloudseed/mcp/token`, `~/.cloudseed/ui/token`; the rest of `~/.cloudseed/mcp/` holds
  client-config backups that can carry the token), `~/.cloudseed/sessions`, the undo journal and backups
  (`~/.cloudseed/undo.json`, `~/.cloudseed/undo/`), and in every environment's working directory
  (`~/.cloudseed/envs/*/` or a custom `--workdir`) `ssh/`, `k8s/`, `vpn/` (`*.ovpn` client profiles with private keys)
  and `platform/` (`platform/secrets.json` and generated manifests).
- Commands marked human-only above (installing software, `use <agent>`/`model <id>`/`enable`/`disable`, `skill install`,
  `ui` and `mcp` other than their read-only forms, `setup mcp`, `creds set|unset|clear`, interactive `ssh`/`k9s`) change
  the user's machine or need a terminal: print the exact command for the user and wait. In an agent session cloudseed
  itself refuses them (exit code 2 with the command for the user); only their read-only forms (`creds list`, `model`,
  `use list`, `install list`, `ui status|logs`, `mcp status|guide|tools|config|test|logs`, `deps status`,
  `skill list|show`) run.
- Never pass secrets on the command line.
- Platform items that need cloud resources (velero, karpenter, external-dns) get them through `cloudseed platform install`, which applies the
  environment's Terraform stack first (plan shown, approval as usual); never create buckets/roles by hand.
- Destructive tests (`chaos run --target`, `dr test`, `dr restore`) change running workloads: say so and get consent before running them.
