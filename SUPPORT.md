# Getting help with cloudseed

cloudseed is maintained in public by [Nimesh Builds](https://github.com/nimeshbuilds). Community support is best
effort; there is no commercial support or response-time guarantee.

## Help yourself first (it is usually fastest)

cloudseed is built to explain itself:

| Command | What it gives you |
|---|---|
| `cloudseed help` / `cloudseed help <command>` | every command and flag, with examples |
| `cloudseed help <topic>` | `quickstart`, `security`, `state`, `deps`, `platform`, `fips`, `vmware`, `troubleshooting`, ... |
| `cloudseed explain <feature>` | how a feature is implemented: files, cloud resources, controls, where its state lives |
| `cloudseed doctor [cloud]` | which tools are installed and how you are authenticated |
| `cloudseed troubleshoot <cloud> --env <name>` | a deterministic diagnosis of the last failed change, with the fix |
| `cloudseed help variables <cloud>` | every Terraform variable you can set with `--var`, and its default |

The [documentation site](https://nimeshbuilds.github.io/cloudseed/) has the quick start, 15 step-by-step scenarios,
guides and the generated reference.

## Where to ask

| You need | Go to |
|---|---|
| Help with a setup, a question, an idea | [GitHub Discussions](https://github.com/nimeshbuilds/cloudseed/discussions) |
| A reproducible bug | [Bug report](https://github.com/nimeshbuilds/cloudseed/issues/new?template=bug_report.yml) |
| A feature or a new scenario | [Feature request](https://github.com/nimeshbuilds/cloudseed/issues/new?template=feature_request.yml) or [Scenario request](https://github.com/nimeshbuilds/cloudseed/issues/new?template=scenario_request.yml) |
| A security vulnerability | [Private report](https://github.com/nimeshbuilds/cloudseed/security/advisories/new), see [SECURITY.md](SECURITY.md) |
| What is planned | [ROADMAP.md](ROADMAP.md) |

## What to include

- the cloudseed version or commit, your OS, and the target (`aws`, `gcp`, `azure`, `vmware`);
- the exact command you ran and what you expected;
- the output of `cloudseed troubleshoot <cloud> --env <name>` and, if useful, the log it points to under
  `<workdir>/logs/`. cloudseed redacts secrets from its own logs, but **read them before posting** and remove
  account, project and subscription IDs, IP addresses and hostnames you consider private.

Never paste credentials, tokens, Terraform state, kubeconfigs or `.ovpn` files anywhere public.

## Problems that belong upstream

If a problem reproduces without cloudseed (a Terraform provider bug, a Helm chart issue, a cloud API limit, a VMware
bug), report it to that project too and link the upstream issue from ours.
