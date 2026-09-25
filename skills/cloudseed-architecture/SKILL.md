---
name: cloudseed-architecture
description: Answer questions about how cloudseed itself works and how a given environment was built - implementation details, which Terraform/Ansible/Helm pieces created what, where state, logs, inventory and secrets live, what security controls apply. Use whenever the user asks "how does cloudseed do X", "what did it create", "where is Y", "why is Z configured like that".
---

# cloudseed architecture (answering implementation questions)

Ground every answer in deterministic sources, in this order:
1. `cloudseed explain <feature>` - features: overview, network, bastion, security-baseline, state, kubernetes, platform, vpn, vmware,
   provisioning, finops, managed-data, agentic, reconcile (how pre-existing resources are adopted), prereqs (cloud resources for
   platform items), mcp, fips, chaos, dr, scan, undo, ui, audit, dependencies. Exact files, controls, state paths and commands.
   `cloudseed explain` with no argument lists every feature, target, command, topic, platform group and item. A word that
   names several things (vmware, security) is taken as feature > target > platform group/item > command/topic, with an
   "also:" line; `cloudseed explain feature|target|topic|command|group|item <name>` picks one explicitly.
   `cloudseed explain variable <cloud> <name>` (or `<cloud> <name>`) explains one setup setting: what it sets, its default,
   the question that asks for it. Add `--json` for the page as data (kind, title, summary, sections, commands, also,
   did_you_mean; exit 1 when nothing matches); over MCP it is `cloudseed_explain` with `format=json` or the resource
   `cloudseed://explain/<query>`, and in the web console the "?" beside a thing opens the same page.
2. `cloudseed inventory <cloud> --env <env>` (add `--json` for detail) - every managed resource with identifiers + the change history
   (applies, destroys, provisioning, platform installs, VPN users, node changes, finops reports).
3. `cloudseed status <cloud> --env <env>` and `cloudseed output <cloud> --env <env> --json` - current configuration and outputs.
4. `cloudseed troubleshoot <cloud> --env <env> --log` - what happened, the failed change (diagnosed before later read-only runs), live checks.
5. `cloudseed help <command|topic>` and `cloudseed help variables|outputs <cloud>` - behaviour and every tunable.

Facts worth knowing without looking up:
- Per environment working directory: config.json, ssh/, stack/main.tf.json (+ local state), bootstrap/, logs/, inventory.json, k8s/, vpn/, platform/, finops/, vms/ (vmware).
- Rendered Terraform roots call the generic stack module in terraform/<target>; variables come from config vars + --var extras.
- Secrets never leave the machine: agents get no secret env vars (child cloudseed commands fetch them from a per-session
  socket) and cloudseed's output is redacted; secrets files are 0600; state contains no credentials.
- Unexpected errors keep a redacted traceback in the env log or `~/.cloudseed/logs/<ts>-<cmd>-crash.log`.
- Everything is idempotent and re-runnable: setup (update), provision, platform install (skip-if-installed), node add.
When unsure, say what you checked and point to the file path or command that holds the answer.
