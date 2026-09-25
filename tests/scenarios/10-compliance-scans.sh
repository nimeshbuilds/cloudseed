#!/usr/bin/env bash
# Scenario 10 - Compliance scans (docs/scenarios/10-compliance-scans.md)
# Default: isolated; FIPS verification, scan all and the reports list run offline against the rendered cluster, and the
# cluster / host scans are checked to say there is nothing to scan yet. CLOUDSEED_LIVE=1: every scan against vmware-lab
# (a FAIL verdict is a finding, not a script failure: exit 0 or 1 are both accepted, the report must exist).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 10-compliance-scans "Compliance scans" vmware
need python3 terraform go

verdict() {   # a scan that ran: exit 0 (PASS) or 1 (FAIL verdict), never a crash or a usage error
  SCN_CHECKS=$((SCN_CHECKS + 1))
  [[ "$SCN_RC" == "0" || "$SCN_RC" == "1" ]] || _scn_fail "expected a verdict (exit 0 or 1), got $SCN_RC"
}

step "Before you start: the scenario 05 cluster"
if [[ "$SCN_LIVE" == "1" ]]; then
  lab_cluster
else
  ok cs setup vmware -y --env lab --var enable_kubernetes=true --dry-run
  ok cs env use vmware-lab
fi
skip "cs install kubescape trivy (installs software; the scans fetch them on first use)"

step "1. Know what each scan checks"
ok cs help scan
has "kube-bench"
ok cs explain scan
has "OpenSCAP|openscap"

step "2. CIS Kubernetes Benchmark"
if live "cs scan cis (kube-bench)"; then
  any cs scan cis; verdict
  has "CIS Kubernetes Benchmark · vmware-lab"
else
  rc 1 cs scan cis
  has "no Kubernetes cluster yet"
fi

step "3. Posture and vulnerabilities"
if live "cs scan kube --framework nsa,mitre,cis-v1.10.0 / cs scan images"; then
  any cs scan kube --framework nsa,mitre,cis-v1.10.0; verdict
  has "Kubernetes posture \(kubescape"
  any cs scan images; verdict
  has "Workload vulnerabilities"
else
  rc 1 cs scan kube --framework nsa,mitre,cis-v1.10.0
  rc 1 cs scan images
fi

step "4. The hosts: CIS and DISA STIG with OpenSCAP"
if live "cs scan host / cs scan stig (OpenSCAP over SSH)"; then
  any cs scan host vmware --env lab --host bastion,k8s; verdict
  has "Host CIS benchmark \(OpenSCAP\)"
  any cs scan stig vmware --env lab --host bastion; verdict
  has "Host STIG benchmark \(OpenSCAP\)"
else
  rc 1 cs scan host vmware --env lab --host bastion,k8s
  has "No SSH-reachable host"
  rc 1 cs scan stig vmware --env lab --host bastion
fi

step "5. FIPS verification and everything at once"
ok cs scan fips vmware --env lab
has "N/A - vmware-lab is not a FIPS environment"
if [[ "$SCN_LIVE" == "1" ]]; then
  any cs scan all; verdict
else
  ok cs scan all
fi
has "Scan summary · vmware-lab"
ok cs scan reports --last 5

step "6. The cloud account"
skip "cs scan cloud aws --env prod (prowler against a real AWS account)"

step "7. Local Well-Architected assessment"
if [[ "$SCN_LIVE" == "1" ]]; then
  any cs scan architecture vmware --env lab --profile lab
else
  rc 3 cs scan architecture vmware --env lab --profile lab
fi
has "Well-Architected screening"
has "INCOMPLETE|FAIL"
check "architecture evidence is saved" bash -c "ls \"$CLOUDSEED_HOME\"/envs/vmware-lab/scans/architecture-*.json"

step "Verify it worked"
ok cs scan reports
# the fips report of step 5 (in live mode `scan all` wrote five newer ones, so it is not among the last five)
has "fips-[0-9]{8}-[0-9]{6} +N/A"
check "reports saved as JSON and Markdown" bash -c "ls \"${CLOUDSEED_HOME:-$HOME/.cloudseed}\"/envs/vmware-lab/scans/fips-*.json \"${CLOUDSEED_HOME:-$HOME/.cloudseed}\"/envs/vmware-lab/scans/fips-*.md"

step "Clean up"
if [[ "$SCN_LIVE" != "1" ]]; then
  ok cs destroy vmware -y --env lab --purge --auto-approve
  ok cs env clear
fi
