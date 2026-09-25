# Security policy

cloudseed creates cloud networks, bastion hosts and Kubernetes clusters, and runs a local web console and MCP server
that can drive them. Security reports are taken seriously and handled privately.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:
**[Report a vulnerability](https://github.com/nimeshbuilds/cloudseed/security/advisories/new)** (Security tab, then
*Report a vulnerability*). Only the maintainers can see the report.

Please include:

- the cloudseed version (`cloudseed help` prints it) or the commit you tested;
- the target (`aws`, `gcp`, `azure`, `vmware`) and your operating system;
- what an attacker can do, and the smallest reproduction you can share;
- sanitized output only: no credentials, tokens, state files, kubeconfigs, `.ovpn` files or account IDs.

What to expect: an acknowledgement when the report has been read, a discussion of severity and a fix in a private
advisory, and credit in the published advisory and the changelog unless you prefer to stay anonymous. cloudseed is
maintained in public by one maintainer on a best-effort basis, so there is no guaranteed response time; critical
issues are prioritised over everything else.

## Supported versions

| Version | Supported |
|---|---|
| `main` and the latest 0.x release | yes |
| older 0.x releases | no, please upgrade |

## Scope

In scope, for example:

- a way for the local web console (`127.0.0.1:7434`) or MCP server (`127.0.0.1:7433`) to be driven without its token,
  from another origin, or from a page framed by another site;
- a secret (cloud keys, vault values, tokens, private keys) reaching an agent's environment, an agent prompt,
  cloudseed's logs or audit trail, the MCP transport or Terraform state without redaction;
- an agent session being able to run a command cloudseed documents as human-only, or a destructive MCP tool running
  without `confirm=true`;
- a stack that exposes something the documentation says is private: SSH open to a wider range than `--allow-ip`, a
  workload with a public address, an unencrypted state bucket, a Kubernetes API endpoint that is public by default;
- files or keys from `~/.cloudseed` leaving your machine during provisioning, or the Ansible hardening being silently
  skipped;
- the VMware provider (`providers/vmdesktop`) or the installers running code that was not verified as documented.

Out of scope:

- vulnerabilities in third-party software cloudseed installs (Terraform providers, Helm charts from the platform
  catalog, cloud CLIs, Ansible, VMware). Please report those upstream; tell us if cloudseed pins an affected version;
- configurations you explicitly chose that weaken the defaults, such as `--var kubernetes_public_endpoint=true`,
  `--no-harden`, `--no-firewall`, `vault` in dev mode, or running with a real `~/.cloudseed` shared between users;
- attacks that already require control of your user account on the machine running cloudseed. The web console, MCP
  server, credential vault and agent broker protect against other origins and against agents, not against your own
  user;
- Codex, Gemini and Grok reading files on your machine. These agents have a full shell; cloudseed documents that only
  its skills keep them away from credential files (Claude Code runs with cloudseed's secret files denied);
- cost or quota surprises (see `cloudseed finops estimate` before you apply).

## Security model in brief

The full model is in `cloudseed help security` and `cloudseed explain <feature>`. The short version:

- **Network**: only the bastion (and the optional VPN host) gets a public address. SSH is allowed from your IP only;
  `0.0.0.0/0`, anything wider than a /8 and lists covering more than two /8s are refused. Workloads and managed
  Kubernetes run in private subnets behind NAT, with private API endpoints by default.
- **Hosts**: key-only SSH, root login and passwords off, encrypted disks, IMDSv2 (AWS), Shielded VM (GCP), Trusted
  Launch (Azure), Ansible hardening (sshd, fail2ban, auditd, unattended security updates, default-deny nftables).
- **Audit**: CloudTrail, GuardDuty and flow logs on AWS; flow, NAT and firewall logs on GCP; Activity Log to Log
  Analytics on Azure. Remote state buckets are versioned, encrypted, private and TLS-only, and the stacks keep no
  secrets in state or outputs.
- **Local services**: the web console and MCP server listen on loopback only, require a token, check `Host` and
  `Origin`, and refuse framing. Destructive MCP tools need `confirm=true` and destructive console actions need an
  explicit tick.
- **Agents**: credentials are stripped from agent processes and handed only to child `cloudseed` commands over a
  per-session Unix socket; prompts and output are redacted line by line; human-only commands are refused in agent
  sessions.
- **FIPS 140 mode** (`--var fips_mode=true`) switches to FIPS endpoints, FIPS node images and FIPS-only algorithms;
  `cloudseed scan fips` verifies it end to end. It is an engineering control, not a certification of your environment.

cloudseed has not had an independent security audit yet. It is 0.x software: review the plan it shows you before
applying, and test in a non-production account first.
