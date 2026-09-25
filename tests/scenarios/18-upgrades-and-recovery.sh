#!/usr/bin/env bash
# Scenario 18 - Drift, upgrades and application recovery (docs/scenarios/18-upgrades-and-recovery.md)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 18-upgrades-and-recovery "Drift, upgrades and application recovery" local
need python3
ok python3 "$SCN_REPO/tests/scenarios/operations-fixture.py"
step "1. Missing deployment evidence cannot produce a successful drift check"
rc 3 cs ops drift aws --env review --json
has '"verdict": "INCOMPLETE"'
step "2. An upgrade needs live prerequisites and a reviewed plan"
rc 3 cs ops upgrade-plan aws --env review --target-version 1.36 --backup before-upgrade --json
has '"verdict": "INCOMPLETE"'
rc 2 cs ops upgrade-apply aws --env review --plan missing.json --json
has 'approve|approval'
step "3. Recovery cannot run without an environment kubeconfig and isolation review"
rc 1 cs ops recovery-plan aws --env review --namespace shop --json
has '"verdict": "FAIL"'
rc 2 cs ops recovery-test aws --env review --namespace shop --json
has 'approve|approval'
check "operation reports persisted" bash -c 'test -n "$(find "$CLOUDSEED_HOME/envs/aws-review/operations" -name "upgrade-plan-*.json" -print -quit)"'
skip "Provider upgrades, node drains, Velero application/volume restoration and data comparisons require a live cluster; unit fixtures exercise command sequencing and failure handling."
