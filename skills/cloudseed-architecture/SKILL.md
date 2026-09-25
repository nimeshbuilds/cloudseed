---
name: cloudseed-architecture
description: Assess an environment against Well-Architected guidance with cloudseed scan architecture, explain its pillars and findings, and answer how cloudseed works or built an environment. Use for architecture assessments, production readiness, reliability, security, cost, performance, sustainability, or implementation questions.
---

# cloudseed architecture

## Well-Architected assessment

Use the existing environment's saved configuration and local evidence:

```bash
cloudseed scan architecture aws --env prod --profile production --max-age-days 30 --json
cloudseed scan architecture gcp --env prod --json
cloudseed scan architecture azure --env prod --json
cloudseed scan architecture vmware --env lab --profile lab --json
```

`production` and 30 days are the defaults. Target/environment selection follows the core cloudseed skill; pass both
explicitly when several environments exist. The assessment queries no cloud APIs, installs no tools and changes no
infrastructure. It reads local configuration and saved evidence, then writes JSON/Markdown reports under the
environment's `scans/` directory. `cloudseed scan reports` lists them. Do not run `doctor`, provisioning, security
scanners, DR drills or chaos experiments just to obtain this local assessment; those are separate actions.

AWS and GCP findings map to six provider pillars. Azure has five pillars, with sustainability shown separately as
additional guidance. VMware reports local infrastructure best practices, not an official cloud framework.
`lab` relaxes production availability expectations; it never turns unknown evidence into a pass. The profile selects
assessment policy and does not change deployment settings. `scan all` remains the security suite and excludes architecture.

Report the overall verdict and its limits:

- `PASS` / exit 0: applicable assessed checks passed. This is not live verification, certification or a complete
  organisational Well-Architected review.
- `FAIL` / exit 1: definite findings need attention; also report any unknowns instead of hiding them behind the failure.
- `INCOMPLETE` / exit 3: evidence is missing, stale or requires manual review. Never describe this as passed.
- Exit 2: invalid arguments; fix the input before retrying.

This initial scanner retains manual review items as UNKNOWN and has no manual-attestation input. A failure-free
assessment therefore remains INCOMPLETE; individual configuration or recovery checks can pass.

Read finding evidence and remediation before recommending changes. Saved configuration represents intended settings;
it does not prove deployed state. Manual workload requirements, recovery objectives and operational processes need
owner review. Do not invent evidence, weaken policy, suppress unknowns or provision resources to produce a green verdict.

Every interface reaches the same scanner: MCP `cloudseed_scan` with `kind=architecture`, `cloud`, `env`,
`profile=production|lab`, `max_age_days=30` and `json=true`; the console's Architecture scan form and Reports view;
or the CLI above. The MCP architecture call does not need `confirm=true`. Use `cloudseed explain architecture --json`
for implementation details and `cloudseed help scan` for arguments.

## Answering implementation questions

Ground every answer in deterministic sources, in this order:
1. `cloudseed explain <feature>` - features: overview, network, bastion, security-baseline, state, kubernetes, platform, vpn, vmware,
   provisioning, finops, managed-data, agentic, reconcile (how pre-existing resources are adopted), prereqs (cloud resources for
   platform items), mcp, fips, chaos, dr, scan, architecture, undo, ui, audit, dependencies. Exact files, controls, state paths and commands.
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
