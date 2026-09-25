## What and why

<!-- The problem this solves and the resulting behaviour. Link the issue: "Fixes #123". -->

## How it was verified

<!-- Tick what you actually ran. Leave the rest unticked; do not claim a live run you did not do. -->

- [ ] Unit tests: `CLOUDSEED_HOME="$(mktemp -d)" python3 -m unittest discover -s tests`
- [ ] Terraform: `terraform fmt -check -recursive terraform` and `make validate` / `make tftest`
- [ ] VMware provider: `go vet ./... && go test ./...` in `providers/vmdesktop`
- [ ] Dry-run of the affected target: `cs setup <cloud> ... --dry-run`
- [ ] Scenario script(s): `tests/scenarios/run.sh ...`
- [ ] Live run on VMware (Fusion / Workstation version: )
- [ ] Live run on a cloud account (which cloud and region: )
- [ ] Docs site builds (`mkdocs build --strict`)

<!-- Paste the relevant, sanitized output or describe the manual check. -->

## Checklist

- [ ] Help text (`cloudseed/help.py`), `cs explain`, the docs (manual, guides, `scripts/gen-docs.py`) and README updated where behaviour changed
- [ ] `CHANGELOG.md` has a line under **Unreleased**
- [ ] Security-sensitive changes (redaction, credentials, agents, MCP `confirm`, console auth, firewall rules,
      hardening) have a test that shows the protection still holds
- [ ] No credentials, state, kubeconfigs, account IDs or unredacted logs in the diff
