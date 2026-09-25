---
title: Operational workflow verification
description: Evidence for the operational roadmap, interface coverage, packaging checks and the cloud acceptance work that remains.
---

# Operational workflow verification

Reviewed on **2026-09-25** in [pull request #7](https://github.com/nimeshbuilds/cloudseed/pull/7).
The operational workflows are implemented across CLI, MCP, the console and bundled agent skills.
Their local and simulated checks do not establish live cloud readiness. No sandbox AWS account, GCP project,
Azure subscription or VMware host was available for this review.

## Implemented scope

The [operations guide](../guides/operations.md) documents all 18 shared operations: health and private-network
diagnostics; lab/team/production profiles; portable specifications; cost, policy and expiry guards; drift;
pinned upgrades; selected application recovery; guarded cloud acceptance; credential storage; and release
integrity/provenance verification. Every operation uses the same typed input and effect contract across interfaces.
Writing an exported specification to a file requires approval; returning the specification as JSON does not.

The [scenario coverage map](../scenarios/interfaces-and-coverage.md) ties every command/subcommand, operation and
platform catalog item to walkthroughs. All 19 numbered scenarios include CLI commands, an agent prompt, a checked
MCP example and console directions. Authentication, interactive terminals and native host prompts remain explicit
human prerequisites. Catalog coverage documents the install/verify/uninstall procedure for each item; it does not
claim that all optional services were installed together or tested in real clusters.

## Evidence

| Boundary | Checks performed | Remaining limit |
|---|---|---|
| Source and shared contracts | Regression tests cover CLI subprocesses, operation validation/approval, structured MCP results, console routing, policy enforcement and failure paths. The CI source matrix runs Python 3.9, 3.12 and 3.14 on Linux/macOS. | Simulated provider responses cannot prove provider permissions, quotas or service behavior. |
| Executable scenarios | All **19 passed**, with **708 checks** and **61 explicitly skipped** live or credential-dependent steps in the isolated source run. Real loopback MCP and console services were exercised. | Skipped steps are not acceptance evidence. |
| Browser console | Opened health and profile workflows in a real browser; verified profile preview leaves configuration unchanged, health retains unknown evidence, and both saved reports are readable in the light theme. | No browser-driven cloud apply or recovery was performed. |
| Terraform and provider | Validation/mock suites cover the supported roots, regional GKE node locations and AKS zone/tier options; regional scaling regressions verify per-zone counts. Go vet, tests and builds run in CI. | No cloud plan/apply or real VMware guest lifecycle was performed. |
| Containers and executables | Native Linux amd64/arm64 containers and Linux/macOS frozen executables build and exercise CLI, MCP and UI paths in CI. Actual macOS packaging exposed and fixed a missing dynamic-module collection path. | Release-only host combinations are additionally checked by the build-only release workflow. |
| Operational safety | Tests exercise stale-plan rejection, cluster identity/CA checks, bounded subprocess capture and timeouts, scoped credentials, keychain failure paths, recovery isolation/cleanup, and guarded network probes. | Native keychain unlock prompts, actual upgrades, application consistency and storage recovery require the target host/cluster. |
| Documentation | Generated-reference freshness, strict MkDocs builds and an executable feature/interface inventory validate documented routes. | Valid instructions cannot guarantee an external service is available. |
| Distribution | Manifest/checksum and provenance-verification tests; pinned build dependencies and build-first release jobs. | No release tag is created by this review; attestation publication occurs only for an authorized version-tag release. |

The first PR unit matrix correctly rejected two fake private-key headers in test fixtures. The fixtures now construct
those markers at runtime so repository secret scanning remains strict. Packaged-runtime checks on that first
implementation passed independently. See the [PR checks](https://github.com/nimeshbuilds/cloudseed/pull/7/checks)
for results at the final commit; a result from an earlier commit is not substituted for those checks.

## Reproduce without cloud accounts

Use the documented development toolchain: Python, Node, Go and Terraform. Keep test state separate from actual
environments, and run against a stable checkout while tests execute.

```bash
export CLOUDSEED_HOME="$(mktemp -d)"
export CLOUDSEED_LIVE=0
python3 -m unittest discover -s tests
make validate tftest
bash tests/scenarios/run.sh
python3 scripts/gen-docs.py --check
python3 -m mkdocs build --strict
```

Install `requirements-docs.txt` in a development virtual environment for the last command. The
[runtime workflow](https://github.com/nimeshbuilds/cloudseed/blob/main/.github/workflows/runtimes.yml) repeats
packaging-specific checks inside the actual container or executable. The
[trusted release workflow](https://github.com/nimeshbuilds/cloudseed/blob/main/.github/workflows/release.yml)
can be dispatched manually to build and test release artifacts without publishing a release.

## Live acceptance remains required

Follow [scenario 19](../scenarios/19-acceptance-and-releases.md) once sandbox identifiers, regions, a spending limit
and cleanup ownership are supplied. The acceptance workflow checks identity, runs an isolated lifecycle and records
cleanup evidence. An estimate is not a billing cap; provider inventory and ongoing charges still require independent
review. Missing evidence must remain incomplete rather than pass.

Also run [scenario 16](../scenarios/16-health-and-network.md) against the deployed private network and
[scenario 18](../scenarios/18-upgrades-and-recovery.md) against the selected application and upgrade target. Verify
actual egress, chart readiness, node rotation, volume contents and recovery objectives. Production profiles are
configuration presets, and the Well-Architected scanner is an evidence-based assessment, not cloud certification.
