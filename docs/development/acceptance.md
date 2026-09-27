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

## Defects exposed by the additional checks

- **Standalone service lifetime:** a detached MCP/console process or console job could reuse its parent's PyInstaller extraction directory and lose assets when the parent exited. Detached copies now request independent extraction directories. The binary tests exercise HTTP resources and a job that survives console shutdown and is recovered on restart.
- **VMware lifecycle:** failure to grow a disk or remove a VM could leave reported state inconsistent with the filesystem or power state. Regression coverage includes actual capacity, failed creation and retry, stop/delete errors, renamed running VM configurations, and partial cleanup. An independent test uses the real Terraform CLI with simulated VMware tools to verify failed creation produces tracked, tainted state that can be replaced, and a corrupt disk still permits normal destroy.
- **Environment locking:** missing lock support, filesystem errors and unexpected locking failures could silently continue. Environment-changing commands now stop before entering their mutation body; read-only discovery still works.
- **Slow console readers:** each SSE connection could accumulate an unlimited queue of job lines. Streams now use coalesced notifications and replay the job's bounded history, including omission markers and stable event IDs. A blocked-reader regression proves output production and completion remain nonblocking without retaining an unlimited backlog.

Local Python 3.14.6 validation passed **3,431 source tests** (21 optional skips). The actual macOS arm64 executable passed all **10 CLI end-to-end tests**, **91 agent/MCP scenario checks**, **66 console/FinOps scenario checks**, and the detached-job regression. Native container checks passed on Linux amd64 and arm64. These counts describe the dependency-review runs before the subsequent lock and cleanup regressions were added; use the latest workflow logs for the final integrated count.

## Coverage by boundary

| Boundary | Automated checks | What still needs a live target |
|---|---|---|
| CLI, environment selection and configuration | Full standard-library suite; all command help; configuration validation; isolated setup/status/inventory/FinOps/undo/error paths | Existing account policy, quotas and provider API behavior |
| Terraform | Formatting; validate every root; mocked Terraform suites; CLI renders and validates all four targets | Apply, refresh, drift, recovery and destroy in disposable accounts or VMs |
| Go VMware provider | Unit and protocol tests; race detector; vet; host cross-builds; failure-path tools simulated in temporary directories | Actual Fusion/Workstation disk expansion, boot, guest IPs, shutdown and cleanup |
| Ansible | Cloudseed's real private-venv installer; syntax checks for all four playbooks on Python 3.12 and 3.14 | Guest changes across Ubuntu/Debian/Amazon Linux, SSH hardening, reboots and FIPS prerequisites |
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

## Maintaining Apple-signed macOS releases

The trusted release workflow requires Apple Developer ID signatures for both macOS architectures before a version tag can publish. The expected Apple team is `QPF2VF2885`. A missing, incomplete, expired, invalid or wrong-team identity stops the macOS job and therefore blocks release publication.

Configure these repository Actions secrets after authorizing the signing key's transfer to GitHub:

| Secret | Value |
|---|---|
| `APPLE_SIGNING_CERTIFICATE_P12` | Base64 encoding of a password-protected PKCS#12 export containing the intended **Developer ID Application** certificate and its private key |
| `APPLE_SIGNING_PASSWORD` | The nonempty password protecting that export |

Export only the intended identity, rather than a collection of keychain identities. Keep the export and password out of the checkout, logs, artifacts and issue comments. GitHub documents the [certificate-to-Actions-secret process](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications). Certificate rotation within the same team only requires replacing the secrets; the workflow discovers the valid identity fingerprint. A team change requires reviewing the workflow's expected team as well.

Each macOS job imports the secret into its own temporary keychain with a random password, checks for exactly one valid Developer ID Application identity for the expected team, and deletes the decoded export immediately after import. Only the public identity fingerprint and temporary directory path are passed to later steps. The cleanup step restores the original keychain search list and removes the temporary keychain even if the build fails. The workflow uses disposable GitHub-hosted runners.

The build passes this identity to PyInstaller so the embedded Python libraries are signed while packaging. Signing only the outer executable afterward cannot sign libraries already inside a one-file archive. PyInstaller also enables hardened runtime when a real identity is selected; see its [macOS signing documentation](https://pyinstaller.org/en/stable/feature-notes.html#macos-binary-code-signing). The workflow verifies the finished signature, expected team, hardened-runtime flag and secure timestamp, then runs the binary tests. Inventories, checksums and attestations describe those final signed bytes.

The packaging wrapper retries only recognized Apple timestamp-service errors, at most three attempts per signing
operation with one- and two-second waits. All signing arguments stay unchanged. Exhausted retries and other errors
stop the build; the wrapper does not remove timestamps, weaken hardened runtime, or bypass final verification.

Use a manual **Trusted releases** workflow run first. When both secrets are configured, it exercises signing and produces inspectable signed artifacts without publishing a release or version-tag attestations. When neither secret is configured, manual runs explicitly produce ad-hoc signed macOS builds; supplying only one secret is an error. Tagged releases always require Developer ID signing and never silently fall back to ad-hoc signing.

For a local build using an identity already in your keychain:

```bash
CLOUDSEED_CODESIGN_IDENTITY="Developer ID Application: Nimesh Pandeya (QPF2VF2885)" bash scripts/build-bundle.sh
```

This does not export the private key. Developer ID signing and GitHub provenance are separate checks. This workflow does **not** submit binaries for Apple notarization; no notarization credentials are configured here, and a valid signature alone does not guarantee Gatekeeper acceptance of a downloaded executable.

`tests/test_apple_release_signing.py` covers missing/invalid secrets, identity selection, verification failures, cleanup and secret-safe errors using fake commands. Those tests do not import a real private key; actual signing is checked by the macOS release jobs.

## Live acceptance still required

Before calling a release fully validated against infrastructure, record its commit, host/runtime/tool versions, target account or project, region, environment name, cost limit and cleanup owner. Use disposable targets with explicit authorization. No live cloud target was selected or provisioned during this review, and the review host has no VMware installation.

1. Create a minimal landing zone. Check its private networks, bastion access, cloud security baseline and remote-state locking. Reapply and confirm no unexpected changes.
2. Add the cluster. Reach its private API through the supported path, confirm node readiness, scale up/down, and verify a restart preserves access.
3. Install platform groups incrementally. Record every selected item's version, readiness, reachable UI and dependency behavior, then test uninstall in reverse dependency order.
4. Test the selected VPN, including user creation, access and revocation. Check both direct CLI and console/MCP calls for the operations exposed there.
5. Write a test workload and volume marker. Run backup and restore, compare object/volume contents, run an isolated chaos drill, and inspect saved scan and cost reports.
6. Destroy the test environment. Independently inventory cloud resources or VM bundles, check for leftover disks, public addresses, buckets and load balancers, and confirm ongoing charges stop. Retain logs and any deliberately retained backup/state data according to the test plan.

Tests that require paid subscriptions, Ubuntu Pro, model/API credentials, or managed service accounts must be labeled untested until those prerequisites are supplied. A successful dry run cannot substitute for these checks.
