---
title: "Undo, audit trail and inventory"
description: "Revert the last change to any environment with cs undo, even a destroy, and see who ran what and when in the audit trail and inventory."
---

# Undo, audit and inventory

Every state-changing action cloudseed performs leaves two records: an **undo entry** with everything needed to revert
it, and an **audit record** with who ran what, when and how it ended. Both work the same from the CLI, the web
console, the MCP server and the agents.

## Undo

```bash
cs undo --list              # the history, newest first
cs undo aws --env dev       # revert the newest action of that environment
cs undo                     # revert the newest action anywhere
cs undo --global            # revert the newest global action (settings, agents, MCP, UI, credentials)
```

Each undo shows its plan and asks for approval like the action it reverts (`--auto-approve` to skip).

### What each action's undo does

| You did | `cs undo` does |
|---|---|
| `setup` change, `apply`, `update-ip` | restores the previous `config.json` and re-applies; the config is rewritten only once that worked |
| the **first** `setup` of an environment | destroys the environment (the working directory is kept) |
| `destroy` (full, even with `--purge`) | re-creates it from the saved configuration and keys (the hosts are new) |
| `destroy --target` | applies again what was removed |
| `node add` / `remove` / `scale` | scales the pool back, removes the added VMs, or re-creates the removed node |
| `platform install` / `uninstall` | uninstalls / re-installs the same items (remembered `--set` values come back) |
| cloud prerequisites of a platform item | restores the previous configuration, except that Velero's bucket and identity stay (they hold the backups) |
| `vpn add-user` / `revoke` | revokes / re-issues the certificate |
| `dr backup` / `dr schedule` | deletes the backup / schedule |
| `dr restore`, `helm uninstall`, other mutating `kubectl` | restores the Velero backup taken right before (Velero needed) |
| `kubectl create/apply` of new objects, label, cordon | deletes exactly those objects, restores the previous values, uncordons |
| `helm install` / `upgrade` / `rollback` | uninstalls or rolls back to the previous revision |
| `k8s kubeconfig` | removes only the contexts it merged and restores your previous current context |
| scans, chaos runs, drills, FinOps reports | removes only their own files and stops experiments |
| `install`, `skill install` | removes what was placed (skills it replaced come back) |
| `env use`, `use`, `model`, `deps runtime` | restores only the settings that command changed |
| `enable` / `disable`, MCP, UI, `creds` | the opposite command, or the previous values |

`cs help undo` has the complete table.

### Scope and limits

- `cs undo` takes the newest entry anywhere. `cs undo <cloud> --env <name>` takes that environment's newest. A cloud or
  `--env` alone only narrows the choice: when several environments match, it asks (or stops in a script).
- `cs undo --id ID` reverts a specific entry from `--list`, once no newer entry of its scope is left.
- `cs undo --id ID --drop` discards an entry that can never succeed, without undoing it.
- The history keeps the newest **15 changes per environment, at most five of one kind**, plus five report entries
  (scans, drills, chaos runs, bookkeeping), which never push a real change out. Global actions have the same limits.
- When the history is used up, or an undo cannot converge, destroy the environment and start over.

### Undo never loses your later edits

- A file you changed since cloudseed wrote it (a generated template, an installed skill) is copied aside as
  `<file>.cloudseed-undo-<time>` (folders under `~/.cloudseed/undo-kept/`) before it is replaced or deleted.
- Settings undos restore only the keys that command changed.
- `cs creds unset` and `clear` keep a copy of the removed values in the journal (mode 0600) until five newer global
  actions push it out; `--forget` keeps none.

### Global entries are yours

Settings, agents, MCP, UI and credential changes are **global** entries. Only you can undo them, with
`cs undo --global` or the web console's Undo panel. Inside an agent session or an MCP call, `cs undo` skips them and
`--global` is refused.

## Audit trail

Every command writes to its environment's working directory, whatever happens:

| File | Contents |
|---|---|
| `logs/audit.jsonl` | one JSON line per run: time, user, host, command and arguments, exit code, duration and `via`: `cli`, `ui` (the web console), `mcp` or the agent that ran it (`builtin`, `claude`, ...) |
| `logs/<timestamp>-<command>.log` | the full, redacted output of the run, including Terraform, Ansible and SSH |
| `inventory.json` | every managed resource with its identifiers and outputs, plus a history of applies, destroys, provisioning, platform installs, VPN users and node changes |

Every audit line also goes to the global trail, `~/.cloudseed/logs/audit.jsonl`, which is where commands without an
environment are recorded. An unexpected error keeps its redacted
traceback in the environment's log, or in `~/.cloudseed/logs/<ts>-<cmd>-crash.log` (0600); `CLOUDSEED_DEBUG=1` also
prints it.

```json
{"at": "2026-09-24T19:09:54Z", "user": "alice", "host": "laptop.local", "command": "finops",
 "argv": ["finops", "estimate", "vmware", "--env", "lab"], "exit_code": 0, "duration_s": 0.0,
 "env": "vmware-lab", "log": "...", "via": "cli"}
```

## Inventory

```bash
cs inventory aws --env dev             # resources and the change history
cs inventory vmware --env lab --last 30
cs inventory gcp --env prod --json     # for scripts
```

The inventory is kept even when a run fails. `destroy --purge` keeps the audit trail and the final inventory under
`~/.cloudseed/logs/purged/<cloud>-<env>/`, and puts `config.json` and the SSH keys into the undo journal so
`cs undo` can re-create the environment.

## Troubleshoot reads all of this for you

```bash
cs troubleshoot aws --env dev --log
```

It walks the audit log, finds the failed change, matches known failure signatures and checks the live environment.
See [Troubleshooting](troubleshooting.md).

## Related

- [Scenario 13 - day-2 operations](../scenarios/13-day-2-operations.md)
- `cs help undo`, `cs explain undo`, `cs explain audit`
