#!/usr/bin/env bash
# Scenario 02 - Secure AWS landing zone (docs/scenarios/02-aws-landing-zone.md)
# Cloud scenario: every command runs against a throw-away home with --dry-run; nothing reaches AWS. The steps that need
# AWS credentials (plan-only, apply, ssh, update-ip) are checked to stop cleanly and listed as skipped.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 02-aws-landing-zone "Secure AWS landing zone" cloud
need python3 terraform

step "1. Get the tools"
ok cs deps status
has "Amazon Web Services"
skip "cs deps install terraform aws (installs into Homebrew / ~/.cloudseed/bin)"
skip "cs deps image + cs --runtime container setup aws ... --dry-run (needs a running Docker or Podman)"
skip "cs deps bundle (builds dist/cloudseed-<os>-<arch>, downloads Terraform)"
ok cs deps runtime local
has "Default runtime set to local"
ok cs deps runtime auto
has "Default runtime set to auto"

step "2. Log in and check"
skip "aws sso login --profile prod (AWS credentials)"
ok cs creds set AWS_PROFILE=prod
has "AWS_PROFILE stored"
# doctor for a named cloud exits 1 while that cloud is not ready (no credentials here): the output is the check
any cs doctor aws
has "terraform"

step "3. See every knob"
ok cs help variables aws
has "single_nat_gateway"
ok cs help outputs aws
has "workload_security_group_id"
ok cs explain state
has "terraform/\*-bootstrap"

step "4. Preview offline with a dry run"
ok cs setup aws -y --env prod --region us-west-2 --allow-ip 203.0.113.7 --dry-run
has "Environment aws-prod"
has "SSH allowed from +203\.0\.113\.7/32"
has "Dry run complete"
check "stack and bootstrap roots rendered" test -f "$CLOUDSEED_HOME/envs/aws-prod/stack/main.tf.json" -a -f "$CLOUDSEED_HOME/envs/aws-prod/bootstrap/main.tf.json"
check "both roots validated" test "$(grep -c 'Success! The configuration is valid' "$SCN_OUT")" -eq 2

step "5. Know the bill"
ok cs finops estimate aws --env prod
has "NAT gateway"
has "total / month"

step "6. Plan against your account, then apply"
skip "cs setup aws ... --plan-only / apply (AWS credentials)"
rc 1 cs plan aws --env prod
has "AWS profile this environment uses does not exist|AWS credentials are missing"

step "7. Look around"
ok cs status aws --env prod
has "Resources in state +0"
ok bash -c "cs output aws --env prod --json | python3 -c 'import json,sys; json.load(sys.stdin)'"
skip "cs ssh aws --env prod (a deployed bastion)"

step "8. Your IP changed"
rc 1 cs update-ip aws --env prod
has "has not been applied yet"
skip "cs update-ip aws --env prod --allow-ip ... --auto-approve (a deployed environment)"

step "9. Change it, remove a part, bring it back"
ok cs setup aws -y --env prod --var single_nat_gateway=false --dry-run
has "single_nat_gateway +false"
has "aws-prod itself is unchanged"
ok cs destroy aws --env prod --select
has "nothing to select"
ok cs destroy aws --env prod --target module.stack.module.bastion
has "nothing to destroy"
skip "cs setup aws --env prod --var single_nat_gateway=false / cs apply aws --env prod (AWS credentials)"

step "Verify it worked"
ok cs inventory aws --env prod
has "Inventory aws-prod"
ok cs troubleshoot aws --env prod
has "Troubleshooting aws-prod"
ok cs explain reconcile
ok cs explain security-baseline
has "CloudTrail"

step "Clean up"
ok cs destroy aws -y --env prod --purge-state --purge --auto-approve
has "Removed .*aws-prod"
ok cs creds unset AWS_PROFILE --forget
