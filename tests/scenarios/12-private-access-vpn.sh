#!/usr/bin/env bash
# Scenario 12 - Private access with OpenVPN or Tailscale (docs/scenarios/12-private-access-vpn.md)
# Cloud scenario: --dry-run in a throw-away home. The VPN user / connect / provisioning commands are checked to stop
# cleanly before the VPN host exists; the apply and the live VPN steps are listed as skipped.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 12-private-access-vpn "Private access with OpenVPN or Tailscale" cloud
need python3 terraform

step "1. How the VPN works"
ok cs help vpn
has "openvpn"
has "tailscale"
ok cs explain vpn
has "Easy-RSA"

step "2. A landing zone with an OpenVPN host"
ok cs setup aws -y --env vpn --region us-west-2 --allow-ip 203.0.113.7 --var enable_vpn=true --dry-run
has "enable_vpn +true"
has "vpn_type +openvpn"
has "Dry run complete"
ok cs finops estimate aws --env vpn
has "vpn host t3.micro"
skip "cs setup aws --env vpn ... --var enable_vpn=true (apply: AWS credentials)"

step "3. Add users and connect"
rc 1 cs vpn add-user aws --env vpn alice
has "not created yet"
rc 1 cs vpn users aws --env vpn
skip "cs install openvpn (installs software)"
rc 1 cs vpn connect aws --env vpn --user alice
ok cs vpn status aws --env vpn
has "Type +openvpn"
has "configured, not created yet"

step "4. Use the private network, then disconnect"
ok bash -c "cs output aws --env vpn --json | python3 -c 'import json,sys; json.load(sys.stdin)'"
ok cs vpn disconnect aws --env vpn
has "VPN is not connected"

step "5. Revoke, re-provision"
rc 1 cs vpn revoke aws --env vpn alice
rc 1 cs vpn provision aws --env vpn
has "no VPN host yet"
rc 1 cs provision aws --env vpn --host vpn
has "no VPN host yet"
skip "cs vpn add-user / connect / revoke / provision against a real VPN host"

step "6. Tailscale instead of OpenVPN"
rc 2 cs creds set TS_AUTHKEY
has "no terminal to ask on"
ok cs setup gcp -y --env mesh --project-id my-gcp-project --region us-central1 --allow-ip 203.0.113.7 --var enable_vpn=true --var vpn_type=tailscale --dry-run
has "vpn_type +tailscale"
has "TS_AUTHKEY"
has "Dry run complete"
ok cs vpn status gcp --env mesh
has "Type +tailscale"
# a stand-in `tailscale` first on PATH: whatever connect does, this machine's own Tailscale is never started
cat >"$SCN_TMP/bin/tailscale" <<FAKE
#!/bin/sh
echo "fake tailscale \$*" >>"$SCN_TMP/tailscale-called"
exit 1
FAKE
chmod +x "$SCN_TMP/bin/tailscale"
rc 1 cs vpn connect gcp --env mesh
has "not created yet"
check "connect refused before running tailscale (no subnet router yet)" test ! -e "$SCN_TMP/tailscale-called"
skip "cs setup gcp --env mesh ... (apply: a GCP project and a tailnet)"

step "Verify it worked"
ok cs troubleshoot aws --env vpn
has "Troubleshooting aws-vpn"

step "Clean up"
ok cs vpn disconnect aws --env vpn
ok cs destroy aws -y --env vpn --purge-state --purge --auto-approve
has "Removed .*aws-vpn"
ok cs destroy gcp -y --env mesh --purge-state --purge --auto-approve
has "Removed .*gcp-mesh"
