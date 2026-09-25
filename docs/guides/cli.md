---
title: "The cloudseed CLI - commands, help, flags and scripting"
description: "A tour of the cloudseed CLI: every command family, built-in help and explain, global flags, environment shorthand, CI use and exit codes."
---

# The CLI

`cloudseed` (short alias: `cs`) is a single, dependency-free Python command. Everything the web console, the MCP
server and the agents do goes through it, so this is the one interface worth knowing well.

!!! tip "`cs` and `cloudseed` are the same command"
    `scripts/install.sh` installs both. These docs use `cloudseed` in the getting-started pages and the shorter `cs`
    in the guides.

## Commands by task

| Task | Commands |
|---|---|
| Build and change environments | `setup <cloud>`, `plan`, `apply`, `destroy` |
| Look around | `list`, `status`, `output`, `inventory`, `doctor` |
| Get in | `ssh`, `update-ip`, `vpn`, `k8s` |
| Harden hosts | `provision` (runs automatically after `setup`) |
| Kubernetes | `env`, `node`, `platform`, `kubectl`, `helm`, `k9s` |
| Resilience and compliance | `dr`, `chaos`, `scan` |
| Money | `finops` |
| Data platforms | `databricks`, `snowflake` |
| Fix and revert | `troubleshoot`, `undo` |
| Tools and runtimes | `install`, `deps` |
| Integrations | `enable` / `disable`, `ui`, `setup mcp` / `mcp`, `creds` |
| Agents | `agents`, `use`, `model`, `agentic` (alias `do`), `skill` |
| Learn | `help`, `explain` |

The [CLI reference](../reference/commands.md) has every command with all its options, generated from the same help
pages the CLI prints.

## A typical session

```bash
cs doctor aws                            # tools, versions, are you logged in?
cs setup aws --env dev                   # questions, a plan, then apply after you approve
cs status aws --env dev                  # config, resource count, outputs, SSH command
cs output aws --env dev --json           # outputs for scripts
cs ssh aws --env dev                     # onto the bastion
cs setup aws --env dev --var az_count=3  # change something: the plan shows just the difference
cs undo aws --env dev                    # changed your mind? back to the previous configuration
cs destroy aws --env dev                 # everything, after you type the environment id
```

## Get onto the bastion

```bash
cs ssh aws --env dev                              # an interactive session with the generated key
cs ssh aws --env dev -- -L 5432:10.0.16.10:5432   # anything after -- goes to ssh: here a port forward
```

SSH host keys are kept per environment (`<workdir>/ssh/known_hosts`), never in `~/.ssh/known_hosts`, so a re-created
bastion on the same address is not refused.

## Tear down, all or part

```bash
cs destroy aws --env dev                                     # everything: type the environment id to confirm
cs destroy aws --env dev --select                            # pick modules and resources from a numbered list
cs destroy aws --env dev --target module.stack.module.bastion   # one Terraform address (repeatable)
cs destroy aws --env dev --purge-state --purge               # also the state bucket and the working directory
```

A partial destroy keeps the configuration, so `cs apply aws --env dev` re-creates what was removed. Terraform also
removes whatever depends on a target: destroying `module.stack.module.network` takes the bastion, the VPN host and the
cluster with it, and the plan lists them. Before an EKS or GKE cluster is destroyed, cloudseed deletes what Kubernetes
created in the cloud (load balancers, Karpenter nodes, volumes of Delete-policy claims), so the cluster must be
reachable. `cs help destroy` lists what stays in each cloud (account-wide AWS settings, for example).

## Built-in help

The CLI documents itself, and the pages are laid out for your terminal width.

```bash
cs help                    # the overview: every command in one screen (so does plain `cs`)
cs help setup              # one command: every flag, with runnable examples
cs help security           # a topic: the security model
cs help variables aws      # every stack variable with its default, generated from terraform/aws
cs help outputs gcp        # every output
cs help aws                # what the target builds and its gotchas (vmware-skill for vmware)
```

Topics: `quickstart`, `security`, `state`, `deps`, `agentic`, `agents`, `envs`, `services`, `vmware`, `platform`,
`fips`, `destroy`, `troubleshooting` and `examples`. They are also on the web in [Help topics](../reference/topics.md).

For *how* something works rather than how to call it, use `explain`:

```bash
cs explain                 # everything that can be explained
cs explain bastion         # files, resources, security controls, state paths and commands
cs explain velero          # a platform item: chart, version, namespace, dependencies, values per target
```

The same explanations appear behind every **?** in the web console and over MCP: see
[Explain everywhere](explain.md).

## Global flags

| Flag | Effect |
|---|---|
| `-y`, `--yes` | never prompt: every answer comes from flags, environment variables or defaults |
| `--runtime local\|container` | run this command locally or in the all-in-one container |
| `--engine docker\|podman` | the container engine for `--runtime container` |
| `--version` | print the version |

Most commands accept these flags after the command too. For the pass-through commands (`kubectl`, `helm`, `k9s`, `ssh`,
`databricks`, `snowflake` and `agentic`), put them **before** the command, because everything after it is handed to
the tool or the agent:

```bash
cs -y kubectl get pods -A
```

## Choosing the environment

Most commands take `<cloud> --env NAME`. `--env` also accepts the environment id that `cs list` shows, and several
commands can leave the cloud out:

```bash
cs status aws --env prod
cs status --env aws-prod
cs status aws-prod
cs status                   # the current environment (cs env use), or the only one
```

When several environments match and none is current, cloudseed asks at a terminal and stops with the list in a
script. It never guesses. For a command that changes things, it only falls back to `dev` when no other environment is
current.

## Scripts and CI

```bash
cs setup gcp -y --env staging --project-id my-proj --region europe-west1 \
  --state remote --allow-ip 203.0.113.7 --var bastion_machine_type=e2-small --auto-approve
```

- `-y` (or `CLOUDSEED_NONINTERACTIVE=1`) never prompts.
- Without `--auto-approve`, `setup`, `apply`, `destroy` and friends print the plan and exit **3**: a free preview.
- A missing tool stops a `-y` run with exit code **2** and the `cloudseed install <tool>` command to run first, unless
  `CLOUDSEED_AUTO_INSTALL=1` approves installs up front.
- `cs output <cloud> --env <name> --json` and `cs inventory ... --json` give machine-readable results.
- Exit codes are listed in [Concepts](../getting-started/concepts.md#plans-approvals-and-exit-codes).

## Environment variables

| Variable | Effect |
|---|---|
| `CLOUDSEED_HOME` | where everything lives (default `~/.cloudseed`) |
| `CLOUDSEED_NONINTERACTIVE=1` | same as `-y` for every command |
| `CLOUDSEED_AUTO_INSTALL=1` | allow `-y` runs to install a missing tool |
| `CLOUDSEED_DEBUG=1` | also print the redacted traceback of an unexpected error (it is always kept in a crash log) |
| `CLOUDSEED_ADOPT=1` | adopt a pre-existing resource without a terminal when its owner cannot be read (`cs explain reconcile`) |
| `CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE=1` | let the built-in agent's approvals pass without a terminal ([agentic mode](agentic.md)) |
| `NO_COLOR` | plain output without colours |

## Errors that tell you what to do

Every error says what went wrong, the likely fix and correct examples for the command you were typing. Typos get a
"did you mean":

```text
$ cs statsu vmware --env lab
  ✖ unknown command 'statsu'. Natural-language tasks need agentic mode:
    cloudseed enable agentic, then  cloudseed agentic "statsu vmware lab"
    did you mean status, setup, agents?
```

Unsafe input is refused before anything runs:

```text
$ cs setup aws --env dev --allow-ip 0.0.0.0/0
  ✖ --allow-ip: Refusing 0.0.0.0/0: the bastion must not be open to the whole internet.
```

Terraform failures are diagnosed too: expired credentials, a GuardDuty detector that already exists, a held state
lock or a missing permission each come with the fix. When the cause is still unclear,
`cs troubleshoot <cloud> --env <name> --log` reads the logs for you ([Troubleshooting](troubleshooting.md)).

## Every command is recorded

Each run appends a line to the audit trail (`~/.cloudseed/logs/audit.jsonl`, and the environment's own
`logs/audit.jsonl`) and keeps its full, redacted output in `logs/<timestamp>-<command>.log`. See
[Undo, audit and inventory](undo-and-audit.md).
