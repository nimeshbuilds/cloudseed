#!/usr/bin/env bash
# Scenario 17 - Profiles, portable specs and guardrails (docs/scenarios/17-profiles-specs-and-guardrails.md)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 17-profiles-specs-and-guardrails "Profiles, portable specs and guardrails" local
need python3
ok python3 "$SCN_REPO/tests/scenarios/operations-fixture.py"
step "1. Preview then save a deployment profile"
ok cs ops profile aws --env review --profile production --json
has '"saved": false'
ok cs ops profile aws --env review --profile lab --approve --json
has '"saved": true'
step "2. Export, validate, compare and import a portable specification"
ok cs ops spec-export aws --env review --output cloudseed.yaml --json
check "specification exists" test -f cloudseed.yaml
ok cs ops spec-validate --input cloudseed.yaml --json
ok cs ops spec-diff aws --env review --input cloudseed.yaml --json
has '"changes": \[\]'
ok cs ops spec-import aws --env review --input cloudseed.yaml --approve --json
has '"saved": true'
step "3. Cost coverage fails closed for an explicit budget"
rc 1 cs ops policy-check aws --env review --params '{"budget_max_monthly":1}' --json
has '"verdict": "BLOCKED"'
rc 1 cs ops expiry-plan aws --env review --json
has '"eligible": false'
rc 2 cs ops expiry-cleanup aws --env review --approve --json
has 'elapsed expires_at|cleanup_opt_in'
skip "Terraform apply and approved expiry cleanup require real owned infrastructure; the scenario never provisions or destroys cloud resources."
