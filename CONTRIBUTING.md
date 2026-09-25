# Contributing to cloudseed

Thanks for helping. cloudseed welcomes bug reports, documentation fixes, new scenarios, platform catalog items,
Terraform improvements and code. Read the [roadmap](ROADMAP.md) before starting something large, and open an issue
first for a new cloud, a new command or a change to the security model so we can agree on the approach before you
write it.

## Good first contributions

- Follow a [scenario](https://nimeshbuilds.github.io/cloudseed/scenarios/) end to end and fix any step that was unclear
  or wrong.
- Reproduce an [open issue](https://github.com/nimeshbuilds/cloudseed/issues) and attach the sanitized output of
  `cloudseed troubleshoot`.
- Improve an error message. Every error should say what went wrong, the likely fix, and an example that works.
- Add a platform catalog item (see [Changing the platform catalog](#changing-the-platform-catalog)).
- Ask for a scenario that is missing with the **Scenario request** issue template.

## Development setup

You need:

| Tool | Version | Used for |
|---|---|---|
| Python | 3.9 or newer | the CLI and its tests (standard library only, no `pip install` needed) |
| Terraform | 1.10 or newer | `make fmt`, `make validate`, `make tftest`, and the dry-run tests |
| Go | the version in `providers/vmdesktop/go.mod` or newer | building and vetting the VMware provider |
| Git, Make, Bash | any recent | scripts and the Makefile |

```bash
git clone https://github.com/YOUR-USERNAME/cloudseed.git
cd cloudseed
./bin/cloudseed help                  # runs straight from the checkout, nothing to build
./scripts/install.sh                  # optional: links `cloudseed` and `cs` onto your PATH (make uninstall removes them)
```

cloudseed keeps all of its state under `CLOUDSEED_HOME` (default `~/.cloudseed`). **While developing, always point it
at a throwaway directory** so you never touch your real environments, keys or credential vault:

```bash
export CLOUDSEED_HOME="$(mktemp -d)"
./bin/cloudseed doctor
```

## Running the checks

Run what your change touches before you open a pull request. CI runs all of them.

### Python unit tests

```bash
CLOUDSEED_HOME="$(mktemp -d)" python3 -m unittest discover -s tests          # or: make test (verbose)
CLOUDSEED_HOME="$(mktemp -d)" python3 -m unittest tests.test_cloudseed       # one module
```

- The suite must pass on **Python 3.9** (the oldest supported version) as well as the newest. If you only have a
  newer Python, `uv run --python 3.9 python -m unittest discover -s tests` is a quick way to check.
- The tests never contact a cloud, a real VMware installation or an agent. `tests/test_cli_e2e.py` renders and
  runs `terraform validate` on every target, so it needs Terraform, Go (it builds the VMware provider) and network
  access to download the Terraform providers the first time. Export `TF_PLUGIN_CACHE_DIR` to reuse the downloads
  between runs, but never share one cache between runs that happen at the same time: `terraform init` rewrites cached
  providers in place and breaks the other run.
- New behaviour needs a test next to it. Mock the cloud and the tools (`subprocess`, `terraform`, `kubectl`); do not
  depend on anything installed in your home directory.

### Terraform

```bash
terraform fmt -check -recursive terraform     # make fmt rewrites instead of checking
make validate                                 # terraform validate every root (builds the VMware provider first)
make tftest                                   # mocked `terraform test` suites in terraform/<cloud>/tests (no cloud access)
```

`terraform/vmware/.terraform.lock.hcl` records the checksum of a VMware provider binary built from source. If your Go
build differs, `make validate` stops at `terraform/vmware` with "doesn't match any of the checksums previously recorded
in the dependency lock file": delete the `registry.local/cloudseed/vmdesktop` block from that lock file in your
checkout and do not commit the change. CI does the same before `make validate`, and cloudseed does it for the roots it
renders.

The stacks under `terraform/` are generic; cloudseed renders a `main.tf.json` root per environment around them. To see
exactly what a change produces for a real configuration, dry-run it (no credentials needed):

```bash
./bin/cloudseed -y setup aws --env dev --allow-ip 203.0.113.7 --state local --dry-run
```

When you add or rename a variable or output, `cloudseed help variables <cloud>` and `cloudseed help outputs <cloud>`
pick it up from the Terraform code automatically; give it a clear `description`.

### VMware provider (Go)

```bash
cd providers/vmdesktop
go vet ./...
go test ./...
go build -mod=readonly -trimpath ./...
```

The unit tests use fakes and never start a VM. `cloudseed install vmware-provider --rebuild` installs your build into
`$CLOUDSEED_HOME/providers` for a real run.

### Scenario scripts

Every scenario on the [documentation site](https://nimeshbuilds.github.io/cloudseed/scenarios/) has a script in
`tests/scenarios/` that runs the documented commands in an isolated `CLOUDSEED_HOME`. `tests/scenarios/run.sh` runs
them and prints a summary table (see the header of `run.sh` for how to run a single scenario). Cloud scenarios run in
dry-run mode (Terraform render + validate, no credentials). Scenarios that create local VMs only run when you opt in
with the environment variable documented in `run.sh`, because they need VMware Fusion Pro or Workstation Pro and
several GB of RAM. If you change a command, flag or output that a scenario page shows, update the page and its
script in the same pull request; `tests/test_scenarios_docs.py` checks that every documented command still parses.

### Documentation site

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-docs.txt
.venv/bin/python scripts/gen-docs.py          # regenerates docs/reference from the CLI itself
.venv/bin/mkdocs serve                        # http://127.0.0.1:8000/cloudseed/
```

Reference pages are generated from `cloudseed help`, the Terraform variables and outputs, the platform catalog and the
MCP tool list, so they cannot drift from the code. Edit the source (help text, `description` fields, the catalog), not
the generated Markdown.

## Where things live

| Path | What it is |
|---|---|
| `cloudseed/` | the CLI (standard library only): `cli.py` commands, `help.py`, `explain.py`, `clouds/` targets, `tf.py`, `platform.py` catalog, `mcp.py`, `webui.py` + `web/` console, `undo.py`, `secrets.py` redaction, ... |
| `terraform/<cloud>/` | the stack for each target, with `modules/` and a mocked `tests/` suite |
| `terraform/<cloud>-bootstrap/` | remote state storage for AWS, GCP and Azure |
| `providers/vmdesktop/` | cloudseed's own Terraform provider for VMware Fusion and Workstation (Go) |
| `ansible/` | bastion, VPN, Kubernetes and scan playbooks and their roles |
| `skills/` | Agent Skills (`SKILL.md`) used by the built-in agent, Claude Code, Codex, Gemini and the MCP server |
| `templates/` | files that `cloudseed platform template` writes, such as the GitLab CI pipeline |
| `tests/` | unit tests (`test_*.py`) and the scenario scripts (`tests/scenarios/`) |
| `docs/`, `mkdocs.yml`, `overrides/` | the documentation site |

`cloudseed explain <feature>` prints which files implement a feature, where its state lives and which commands drive
it. It is the fastest way to find your way around.

### Changing the platform catalog

Catalog items live in `CATALOG` in `cloudseed/platform.py`. Pin the chart version, declare dependencies instead of
installing them yourself, adapt values per target and distro, and state whether the item works in FIPS mode and on
arm64. Items that need cloud resources (a bucket, an identity) declare them as prerequisites so they are created by the
environment's own Terraform stack rather than by ad-hoc CLI calls. Check your item with `cs platform info <item>` and
`cs platform plan <item>`, and add it to `cloudseed/explain.py` if it needs more than a line of explanation.

### Changing security-sensitive behaviour

Changes to redaction (`cloudseed/secrets.py`), the credential broker, agent permissions, the MCP `confirm` rules, the
web console's token and origin checks, SSH allow-lists or the Ansible hardening roles need a test that shows the
protection still holds, and a short explanation in the pull request. Report vulnerabilities privately, see
[SECURITY.md](SECURITY.md).

## Pull requests

- Keep each pull request focused on one change and explain the problem, the resulting behaviour and **the checks you
  actually ran** (unit tests, `make validate`, a dry-run, a live VMware run, a real cloud apply). Do not claim a live
  test you did not run.
- Update the help text (`cloudseed/help.py`), `cs explain`, the docs (the manual `docs/guides/manual.md` and the guide
  pages; `python3 scripts/gen-docs.py` for the reference) and `README.md` when behaviour changes, and add a
  line to `CHANGELOG.md` under **Unreleased**.
- Never commit credentials, state files, kubeconfigs, `.ovpn` files, account or subscription IDs, or unredacted logs.
  Output from `cloudseed` itself is already redacted; output from other tools may not be.

### Commit messages

Write a short imperative subject that starts with the area you changed, then a body that explains why:

```
aws: tag the flow-log group with CloudseedEnvId

Reconcile could not tell the log group apart from one created by another
environment in the same account.
```

Common areas: `cli`, `aws`, `gcp`, `azure`, `vmware`, `provider`, `ansible`, `platform`, `dr`, `chaos`, `scan`, `mcp`,
`agentic`, `ui`, `undo`, `docs`, `scenarios`, `ci`.

### No CLA, no DCO sign-off

You keep the copyright of your contribution and license it under the project's [Apache-2.0 license](LICENSE) by
submitting it (section 5 of the license). There is no Contributor License Agreement to sign and no `Signed-off-by`
line is required.

AI-assisted contributions are welcome. The author of the pull request is responsible for its correctness and for the
validation it claims.

## Community

Be kind and constructive: participation follows the [code of conduct](CODE_OF_CONDUCT.md). Questions and ideas go to
[GitHub Discussions](https://github.com/nimeshbuilds/cloudseed/discussions); see [SUPPORT.md](SUPPORT.md) for where
to ask what.
