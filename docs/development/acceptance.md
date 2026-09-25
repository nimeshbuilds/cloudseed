---
title: Runtime acceptance coverage
description: What Cloudseed's automated checks prove, what the dependency reviews found, and what remains to validate against live infrastructure.
---

# Runtime acceptance coverage

Cloudseed has three execution runtimes: the Python checkout, an all-in-one Linux container, and a PyInstaller executable. A passing source test suite does not prove that the container builds or that a detached service can still read packaged assets. The expanded workflows test those boundaries explicitly.

## Dependency pull requests

| Change | Review result |
|---|---|
| [Python container 3.12 → 3.14](https://github.com/nimeshbuilds/cloudseed/pull/1) | The pinned image covers both Linux architectures. Add Python 3.14 to the source matrix, build both real container architectures, and test standalone binaries and their detached services. |
| [Terraform Plugin Framework 1.15 → 1.19](https://github.com/nimeshbuilds/cloudseed/pull/2) | The update requires Go 1.25. Cloudseed's dependency checks and documentation must match. New NICs require `UseNonNullStateForUnknown` so generated MACs remain unknown until creation. A protocol-level regression exercises the actual framework plan response. |

The framework review used the [upstream changelog](https://github.com/hashicorp/terraform-plugin-framework/blob/v1.19.0/CHANGELOG.md). The provider passed race tests and vet using both Go 1.27.1 and its exact minimum Go 1.25.0, plus builds for macOS arm64/amd64, Linux arm64/amd64 and Windows amd64. A Windows cross-build verifies compilation, not a working Windows control plane.

## Coverage by boundary

| Boundary | Automated checks | What still needs a live target |
|---|---|---|
| CLI, environment selection and configuration | Full standard-library suite; all command help; configuration validation; isolated setup/status/inventory/FinOps/undo/error paths | Existing account policy, quotas and provider API behavior |
| Terraform | Formatting; validate every root; mocked Terraform suites; CLI renders and validates all four targets | Apply, refresh, drift, recovery and destroy in disposable accounts or VMs |
| Go VMware provider | Unit and protocol tests; race detector; vet; host cross-builds; failure-path tools simulated in temporary directories | Actual Fusion/Workstation disk expansion, boot, guest IPs, shutdown and cleanup |
| Ansible | Cloudseed's real private-venv installer; syntax checks for all six playbooks on Python 3.12 and 3.14 | Guest changes across Ubuntu/Debian/Amazon Linux, SSH hardening, reboots and FIPS prerequisites |
| Container | Native Linux amd64/arm64 Docker builds; every included executable starts; CLI end-to-end and local service scenarios inside the image | Authenticated cloud calls, mounted real user credentials and rootless-engine behavior |
| Standalone binary | Actual Linux/macOS PyInstaller builds; packaged-data checks; the CLI end-to-end suite targets the executable; real MCP and console scenarios | Signed release distribution and other host/architecture combinations |
| MCP | HTTP and stdio requests; authentication, resources, tools, token rotation, stop/restart and cleanup | Each third-party client's interactive installation and login |
| Web console | Real loopback API; setup dry run; jobs and activity; authentication, origin rejection, token rotation and restart | Browser-driven cloud apply and live operational actions |
| Agents | Offline echo adapter, secret stripping/redaction, human-only command refusal, built-in tool contracts | Actual model execution and each external agent's own permission system |
| Kubernetes and platform catalog | Dependency ordering, manifests, command generation, prerequisite rendering, mocked control-plane responses | Install/readiness/uninstall of each item on supported cluster versions |
| VPN, DR, chaos and scans | Command contracts, generated configuration, report parsing, deterministic failure paths | Tunnels and revocation; backup/restore with volume checksums; injected failures; scanner results from real hosts/clusters |
| Costs and managed services | Offline estimates, report contracts, profile handling and mocked APIs | Billing permissions/data, OpenCost, Databricks and Snowflake authentication |
| Documentation | Strict build, generated-reference freshness, internal links, desktop/mobile browser interaction | Nothing here establishes infrastructure readiness |

“Scenario passed” means its implemented assertions passed. Cloud scenarios always use Terraform **dry runs**, even when `CLOUDSEED_LIVE=1`; that switch enables the VMware scenarios only. The scenario runner reports skipped optional steps. CI checks do not silently count those skipped steps as live coverage.

## Reproduce the checks

The full matrix lives in [tests.yml](https://github.com/nimeshbuilds/cloudseed/blob/main/.github/workflows/tests.yml) and [runtimes.yml](https://github.com/nimeshbuilds/cloudseed/blob/main/.github/workflows/runtimes.yml). Both run on pull requests and main, with read-only repository permissions. The runtime workflow builds temporary images and binaries without publishing them.

For a checkout with the documented tools installed:

```bash
python3 -m unittest discover -s tests
make validate
make tftest
bash tests/scenarios/run.sh
```

To point the CLI end-to-end battery and local service scenarios at a built executable:

```bash
export CLOUDSEED_TEST_BINARY="$(pwd)/dist/cloudseed-darwin-arm64" # choose your actual artifact
python3 -m unittest tests.test_cli_e2e
export SCN_BINARY="$CLOUDSEED_TEST_BINARY"
bash tests/scenarios/14-ai-agents-and-mcp.sh
bash tests/scenarios/15-web-console-and-finops.sh
```

The scenario helpers use temporary homes and remove their test resources. The ordinary unit suite also uses isolated fixtures; run it in a development checkout, not against a production environment.

## Live acceptance still required

Before calling a release fully validated against infrastructure, record its commit, host/runtime/tool versions, target account or project, region, environment name, cost limit and cleanup owner. Use disposable targets with explicit authorization. No live cloud account or VMware installation was available for this review.

1. Create a minimal landing zone. Check its private networks, bastion access, cloud security baseline and remote-state locking. Reapply and confirm no unexpected changes.
2. Add the cluster. Reach its private API through the supported path, confirm node readiness, scale up/down, and verify a restart preserves access.
3. Install platform groups incrementally. Record every selected item's version, readiness, reachable UI and dependency behavior, then test uninstall in reverse dependency order.
4. Test the selected VPN, including user creation, access and revocation. Check both direct CLI and console/MCP calls for the operations exposed there.
5. Write a test workload and volume marker. Run backup and restore, compare object/volume contents, run an isolated chaos drill, and inspect saved scan and cost reports.
6. Destroy the test environment. Independently inventory cloud resources or VM bundles, check for leftover disks, public addresses, buckets and load balancers, and confirm ongoing charges stop. Retain logs and any deliberately retained backup/state data according to the test plan.

Tests that require paid subscriptions, Ubuntu Pro, model/API credentials, or managed service accounts must be labeled untested until those prerequisites are supplied. A successful dry run cannot substitute for these checks.
