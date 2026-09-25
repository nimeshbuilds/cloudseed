#!/usr/bin/env bash
# Scenario 16 - Health and private networking (docs/scenarios/16-health-and-network.md)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 16-health-and-network "Health and private networking" local
need python3
step "1. Seed an isolated saved configuration (no cloud resources)"
ok python3 "$SCN_REPO/tests/scenarios/operations-fixture.py"
step "2. Inspect saved health and network evidence"
rc 3 cs ops health aws --env review --json
has '"verdict": "INCOMPLETE"'
rc 3 cs ops network aws --env review --json
has '"verdict": "INCOMPLETE"'
check "health report persisted" bash -c 'test -n "$(find "$CLOUDSEED_HOME/envs/aws-review/scans" -name "health-*.json" -print -quit)"'
check "network report persisted" bash -c 'test -n "$(find "$CLOUDSEED_HOME/envs/aws-review/scans" -name "network-*.json" -print -quit)"'
step "3. Guard active probes"
rc 2 cs ops network aws --env review --active --live --json
has 'approval|approve'
ok cs ops list --json
has 'cloudseed_ops_network'
skip "Live API readiness and temporary-pod DNS/TLS/registry probes require a deployed cluster and explicit active-probe approval."
