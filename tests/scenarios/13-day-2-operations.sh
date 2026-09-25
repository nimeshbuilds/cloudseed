#!/usr/bin/env bash
# Scenario 13 - Day-2 operations (docs/scenarios/13-day-2-operations.md)
# Default: isolated; inventory, audit trail, undo journal (incl. --drop), troubleshooting and the credential vault run
# against a rendered environment, and the node / provisioning commands are checked to say the cluster is not created
# yet. CLOUDSEED_LIVE=1: node add + remove, a setting change + undo, plan / apply and re-provisioning on vmware-lab.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 13-day-2-operations "Day-2 operations" vmware
need python3 terraform go
HOME_DIR="${CLOUDSEED_HOME:-$HOME/.cloudseed}"

step "Before you start: the scenario 05 cluster"
if [[ "$SCN_LIVE" == "1" ]]; then
  lab_cluster
else
  ok cs setup vmware -y --env lab --var enable_kubernetes=true --dry-run
  ok cs env use vmware-lab
fi

step "1. What exists, and who changed what"
ok cs list
has "vmware-lab"
ok cs status vmware --env lab
has "Environment vmware-lab"
ok cs inventory vmware --env lab --last 5
has "Inventory vmware-lab"
ok tail -n 3 "$HOME_DIR/envs/vmware-lab/logs/audit.jsonl"
has '"command": "inventory"'
has '"via": "cli"'

step "2. Add and remove a node"
if live "cs node add --count 1 / cs node list / cs node remove cloudseed-lab-wk3 (~8 min)"; then
  ok cs -y node add --count 1 vmware --env lab --auto-approve
  ok cs node list
  has "cloudseed-lab-wk3"
  ok cs -y node remove cloudseed-lab-wk3 vmware --env lab --auto-approve
  ok cs node list
  hasnt "cloudseed-lab-wk3"
else
  rc 1 cs node add --count 1 vmware --env lab
  has "not created yet"
  rc 1 cs node list
  rc 1 cs node remove cloudseed-lab-wk3 vmware --env lab
fi
skip "cs node scale aws --env prod --count 3 --max 6 (an EKS cluster)"

step "3. Change a setting, then undo it"
if live "cs setup vmware --env lab --var workload_count=1 / cs undo vmware --env lab / plan / apply"; then
  ok cs setup vmware -y --env lab --var workload_count=1 --auto-approve
  ok cs status vmware --env lab
  has "workload_private_ips"
  ok cs undo --list
  has "setup vmware-lab \(changed: workload_count\)"
  ok cs -y undo vmware --env lab --auto-approve
  ok cs plan vmware --env lab
  ok cs -y apply vmware --env lab --auto-approve
else
  ok cs setup vmware -y --env lab --var workload_count=1 --dry-run
  has "workload_count +1"
  has "vmware-lab itself is unchanged"
  ok cs undo --list
fi

step "4. Diagnose, don't guess"
ok cs troubleshoot vmware --env lab --log
has "Troubleshooting vmware-lab"
ok cs doctor vmware
has "VMware Fusion / Workstation"

step "5. Re-provision a host and handle a new IP"
if live "cs provision vmware --env lab --host bastion"; then
  ok cs -y provision vmware --env lab --host bastion
else
  rc 1 cs provision vmware --env lab --host bastion
  has "has not been applied yet"
fi
ok cs update-ip vmware --env lab
has "update-ip does not apply to vmware"
skip "cs update-ip aws --env prod (a deployed AWS environment)"

step "6. The credential vault"
# (live mode: in a throw-away home - see vault in lib.sh - so your real vault and global undo history stay untouched)
ok vault cs creds set AWS_PROFILE=prod
has "AWS_PROFILE stored"
rc 2 vault cs creds set ANTHROPIC_API_KEY
has "no terminal to ask on"
ok vault cs creds list
has "AWS_PROFILE +stored +prod"
ok vault cs creds unset AWS_PROFILE
has "AWS_PROFILE removed"
rc 3 vault cs undo --global
has "Nothing applied"
ok vault cs undo --global --auto-approve
ok vault cs creds list
has "AWS_PROFILE +stored +prod"
ok vault cs undo --list
ID="$(grep -Eo 'id [0-9]{8}-[0-9]{6}-[0-9a-f]{6}' "$SCN_OUT" | head -n 1 | awk '{print $2}')"
check "an undo id to drop" test -n "$ID"
ok vault cs undo --id "$ID" --drop
ok vault cs creds clear --forget
has "Credential vault cleared"

step "Verify it worked"
if [[ "$SCN_LIVE" == "1" ]]; then
  ok cs node list
  hasnt "cloudseed-lab-wk3"
fi
ok cs undo --list
ok cs inventory vmware --env lab --last 10
ok cs explain undo
has "journal"
ok cs explain audit
has "audit.jsonl"
ok cs help troubleshooting

step "Clean up"
if [[ "$SCN_LIVE" != "1" ]]; then
  ok cs destroy vmware -y --env lab --purge --auto-approve
  ok cs env clear
fi
