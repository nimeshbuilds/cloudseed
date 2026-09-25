# CI failure analysis and repair

The failing `tests` workflow was exposing existing runtime bugs and test-environment assumptions. The failures were present on `main` and repeated on both Dependabot pull requests; they were not introduced by those dependency updates. The GitHub Pages workflow itself was already succeeding.

## Evidence

- [Main tests run](https://github.com/nimeshbuilds/cloudseed/actions/runs/36084684887): all four Python jobs and the scenario job failed. Terraform validation/tests and Go validation/builds passed.
- [Go dependency pull request run](https://github.com/nimeshbuilds/cloudseed/actions/runs/36084775208): the same unit/scenario failure pattern.
- [Python container pull request run](https://github.com/nimeshbuilds/cloudseed/actions/runs/36084734546): the same pattern, plus an intermittent adopted-job completion failure on macOS.
- [Successful Pages run](https://github.com/nimeshbuilds/cloudseed/actions/runs/36084684824).

Each original Python job ran 3,423 tests. The scenario job passed 10 scripts and failed five: first VMware lab, Azure private AKS, local Kubernetes, day-2 operations, and agents/MCP.

## Causes and changes

| Area | Failure | Repair |
| --- | --- | --- |
| MCP lifecycle on Linux | `ps` truncated long command lines, hiding `mcp serve --http`. The ownership guard refused to stop its own server, leaving ports occupied during rotation/restart. | Read the full process command line with `ps -ww`; retain the existing process-identity check. Add a long-command regression with narrow terminal columns. |
| Explicit Google credentials | An installed `gcloud` caused live ADC checks to hide a malformed `GOOGLE_APPLICATION_CREDENTIALS` file. | Validate the explicitly selected credential file before querying the CLI, preserving the specific repair guidance. |
| Local HTTP server startup | Python's default HTTP server binding performs reverse DNS. Slow resolver behavior can exceed console and fixture startup deadlines on macOS. | Bind MCP/UI servers using the literal address without reverse DNS. The OpenCost test server uses the same deterministic approach. Regression tests refuse any DNS lookup during binding. |
| Adopted UI jobs | Completion could become visible before terminal metadata was persisted, so a reader could see a completed job with `rc: null` on disk. | Synchronize terminal-state visibility and metadata persistence; test the ordering with a deliberately delayed write. |
| Azure scan preflight | The presence of `az` was treated as proof of a login. An unauthenticated runner installed Prowler and attempted a scan before reporting missing credentials. | Check for an Azure CLI account before installing or invoking Prowler. Explicit service-principal and managed-identity modes retain their existing behavior. |
| VMware command ordering | The top-level runtime check demanded VMware before node/provision handlers could report that the environment had never been applied. | Let those handlers validate existing state first and prepare the hypervisor only where an operation requires it. |
| Browser help rendering tests | A large JavaScript program passed through `node -e` exceeded Linux's per-argument size limit (`E2BIG`). | Send the program over standard input instead. |
| Client-configuration isolation | Inherited `XDG_CONFIG_HOME` escaped temporary `HOME` directories on Linux, causing fixture collisions and configuration writes outside the fixture. | Isolate and restore the configuration directory in the MCP fixture; scrub inherited XDG paths in isolated scenarios. |
| Manifest rendering tests | The MetalLB warning probe invoked a real `kubectl` even though these were offline rendering tests. | Stub that cluster-inspection boundary while still exercising the real manifest rendering/application path. |
| Scenario expectations | Dry-run VMware hosts were expected to pass a readiness check despite lacking VMware. Temporary service scenarios could install login items. | Check readiness output in dry-run mode, preserve strict readiness in live mode, and exercise local MCP/UI servers as background processes. |
| Terminal fixtures | Spinner tests simulated a terminal but inherited the caller's `TERM=dumb` capability state. | Explicitly enable the terminal capability being exercised inside the fixture. |

The dependency checks remain enabled. No failing feature was removed from the suite, and no live cloud or VMware infrastructure was provisioned during this repair.

## Workflow improvements

The tests workflow now installs Node explicitly, so JavaScript checks do not depend on the hosted image's incidental tool inventory. Failed unit and scenario jobs upload their complete logs as artifacts with seven-day retention. The existing Python/macOS/Linux matrix, Terraform checks, Go tests, and cross-compilation remain in place.

The Pages workflow builds documentation in strict mode on pull requests. Pull requests cannot deploy Pages; deployment permissions are scoped to the deployment job, and separate concurrency groups keep a pull-request validation from interfering with a main-branch deployment.

The follow-up Python 3.14 matrix exposed an intermittent macOS Ctrl-C fixture failure: the parent forwarded the interrupt, but the shell-based fake Terraform did not run its trap. The shell/fork interaction is the suspected cause, not a reproduced production failure. A separate exercise with real Terraform 1.16.4 and a local-only `terraform_data` resource verified graceful interruption, saved state and released locking. The fixture now uses one Python process with explicit signal-handler readiness, checks exactly one forwarded interrupt, and joins its sender to prevent a late signal from affecting another test. Production signal handling is unchanged.

## Verification

The final [pre-merge tests run](https://github.com/nimeshbuilds/cloudseed/actions/runs/36088389520) passed all seven jobs on commit `bb5a778`: four Python/OS combinations, Terraform, the Go provider, and all 15 scenario scripts. Each Python job ran **3,431 tests** with **19–23 skips**. The [strict documentation build](https://github.com/nimeshbuilds/cloudseed/actions/runs/36088389478) passed. PR #3 was merged, and the [Pages deployment](https://github.com/nimeshbuilds/cloudseed/actions/runs/36089299031) succeeded. The deployed white-and-blue site and interactive target tabs were checked in the browser with no console errors.

The results below describe the earlier local investigation. See [runtime acceptance coverage](acceptance.md) for the subsequent dependency reviews and packaged-runtime testing.

A complete local run executed **3,431 tests in 265.6 seconds**, with **23 skips**. It found two regressions from the accompanying branding changes: the new wordmarks lacked the existing explicit tagline-width geometry, and the repository-layout guide omitted the new asset generator. Both were corrected without removing assertions. A subsequent **38-test focused run passed**, covering web styling/asset geometry and the installation/layout guide. The complete run was not repeated after those two asset/documentation corrections; it is not reported as an entirely green full-suite run.

All original runtime failures passed in that complete run, including MCP lifecycle, credential diagnostics, local server startup, manifest rendering, help reflow, OpenCost forwarding, Azure scan authentication, and terminal rendering. The new deterministic adopted-job persistence regression also passed. Skips cover unavailable optional libraries/tools, Python-version-specific checks, signal-handler constraints, and explicitly enabled browser/Terraform suites.

All five scenario scripts that failed in the original run now pass locally. The console/FinOps scenario also passes its **66 checks**, including API authentication, origin rejection, a Terraform dry run, job output, token rotation, restart, foreground serving, and cleanup.

`actionlint`, Python compilation, changed shell-script syntax checks, and `git diff --check` pass. The first pull-request run also passed its [strict documentation build](https://github.com/nimeshbuilds/cloudseed/actions/runs/36087996333) and [Terraform and Go jobs](https://github.com/nimeshbuilds/cloudseed/actions/runs/36087996384). Follow the final hosted Linux/macOS matrix and its logs on [pull request #3](https://github.com/nimeshbuilds/cloudseed/pull/3).

Documentation verification includes a strict MkDocs build and a **53-page internal-link check with no broken targets**. Browser checks cover desktop and 390-pixel mobile layouts, light/dark themes, keyboard-operated cloud tabs, screenshot selection, copy feedback, the mobile navigation drawer, and search. The browser console reported no errors during these checks.

Local verification uses macOS arm64, Python 3.9.6, Terraform 1.16.4, and Go 1.27.1. Cloud authentication, paid cloud resources, real VMware VMs, and operating-system login services require separate live acceptance testing.
