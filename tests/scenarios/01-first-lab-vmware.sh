#!/usr/bin/env bash
# Scenario 01 - Your first lab on your laptop (docs/scenarios/01-first-lab-vmware.md)
# Default: isolated dry run (render + terraform validate, no VMs). CLOUDSEED_LIVE=1: builds and destroys vmware-first.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 01-first-lab-vmware "Your first lab on your laptop" vmware
need python3 terraform go

step "1. Check your machine"
ok cs --version
has "^ *cloudseed [0-9]+\.[0-9]+"
ok cs doctor vmware
has "VMware Fusion / Workstation"
ok cs help
has "CORE COMMANDS"
ok cs help quickstart
has "QUICKSTART"
ok cs help vmware
has "LOCAL VIRTUAL MACHINES"

step "2. Preview the environment"
ok cs setup vmware -y --env first --dry-run
has "Environment vmware-first"
has "Success! The configuration is valid"
has "Dry run complete"
check "config.json saved" test -f "${CLOUDSEED_HOME:-$HOME/.cloudseed}/envs/vmware-first/config.json"

step "3. Build it"
if live "cs setup vmware -y --env first --auto-approve (bastion VM + Ansible hardening, ~10 min)"; then
  on_exit cs destroy vmware -y --env first --purge --auto-approve
  ok cs setup vmware -y --env first --auto-approve
  has "vmware-first is ready"
fi

step "4. Look around"
ok cs list
has "vmware-first"
ok cs status vmware --env first
has "Environment vmware-first"
ok cs output vmware --env first
ok cs output vmware --env first --json
if [[ "$SCN_LIVE" == "1" ]]; then
  has '"bastion_public_ip"'
else
  has '^\{\}$'
fi

step "5. SSH in"
if live "cs ssh vmware --env first -- uptime / sudo sshd -T (hardening check)"; then
  ok cs ssh vmware --env first -- uptime
  has "load average"
  ok bash -c "cs ssh vmware --env first -- sudo sshd -T | grep -E '^(passwordauthentication|permitrootlogin) '"
  has "^passwordauthentication no"
  has "^permitrootlogin no"
else
  rc 1 cs ssh vmware --env first -- uptime
  has "has not been applied yet"
fi

step "Verify it worked"
ok cs inventory vmware --env first
has "Inventory vmware-first"
ok cs troubleshoot vmware --env first
has "Troubleshooting vmware-first"
ok cs explain vmware
has "providers/vmdesktop"
ok cs explain provisioning
has "ansible"

step "Clean up"
if [[ "$SCN_LIVE" == "1" ]]; then
  rc 3 cs destroy vmware --env first      # without a terminal and --auto-approve: the destroy plan only
else
  ok cs destroy vmware --env first        # nothing deployed: says so and exits 0
fi
ok cs destroy vmware -y --env first --purge --auto-approve
has "Removed .*vmware-first"
ok cs list
hasnt "vmware-first"
