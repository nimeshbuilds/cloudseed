#!/usr/bin/env bash
# Scenario 11 - FIPS 140 mode (docs/scenarios/11-fips-140-mode.md)
# Default: isolated; the AWS and VMware FIPS environments are rendered, every refusal is checked, and cs scan fips runs
# offline. CLOUDSEED_LIVE=1 with UBUNTU_PRO_TOKEN exported: also builds vmware-fipslab and verifies it on the hosts.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 11-fips-140-mode "FIPS 140 mode" vmware
need python3 terraform go

step "1. Read what FIPS mode does"
ok cs help fips
has "FIPS 140 MODE"
ok cs explain fips
has "fips"

step "2. Render an AWS FIPS environment"
ok cs setup aws -y --env fips --region us-east-1 --allow-ip 203.0.113.7 --var fips_mode=true --var enable_kubernetes=true --var enable_vpn=true --dry-run
has "Generating an RSA-4096 SSH key pair \(FIPS mode\)"
has "fips_mode +true"
has "UBUNTU_PRO_TOKEN"
has "Dry run complete"

step "3. See what FIPS mode refuses"
rc 1 cs setup aws -y --env fips-eu --region eu-west-1 --allow-ip 203.0.113.7 --var fips_mode=true --dry-run
has "cannot be FIPS-compliant"
has "region eu-west-1"
rc 1 cs setup vmware -y --env fipslab --var fips_mode=true --var enable_kubernetes=true --var kubernetes_distro=kubeadm --dry-run
has "kubernetes_distro=kubeadm: upstream kubeadm binaries are not FIPS builds"
rc 1 cs setup gcp -y --env fipsts --project-id my-gcp-project --allow-ip 203.0.113.7 --var fips_mode=true --var enable_vpn=true --var vpn_type=tailscale --dry-run
has "vpn_type=tailscale"
ok cs list
hasnt "fips-eu|fipsts"

step "4. Verify offline"
ok cs scan fips aws --env fips
has "AWS provider uses FIPS endpoints"
has "PASS - 3 passed, 0 failed"

step "5. The platform catalog in a FIPS environment"
ok cs platform plan basek8s aws --env fips
has "FIPS: user-facing TLS is pinned to 1.2\+"
ok cs platform plan ai aws --env fips
has "not FIPS-capable - skip"

step "6. A FIPS lab on VMware"
rc 2 vault cs creds set UBUNTU_PRO_TOKEN
has "no terminal to ask on"
ok cs setup vmware -y --env fipslab --var fips_mode=true --dry-run
has "RSA-4096"
has "Dry run complete"
if [[ "$SCN_LIVE" == "1" && -n "${UBUNTU_PRO_TOKEN:-}" ]]; then
  on_exit cs destroy vmware -y --env fipslab --purge --auto-approve
  ok cs setup vmware -y --env fipslab --var fips_mode=true --auto-approve
  ok cs ssh vmware --env fipslab -- cat /proc/sys/crypto/fips_enabled
  has "^1$"
  ok cs scan fips vmware --env fipslab
  has "^ *│ PASS"
else
  skip "cs setup vmware --env fipslab --var fips_mode=true + host checks (CLOUDSEED_LIVE=1 and an Ubuntu Pro token)"
  ok cs scan fips vmware --env fipslab
  has "PASS - 2 passed, 0 failed"
fi

step "Verify it worked"
ok cs scan reports aws --env fips --last 3
has "fips-[0-9]{8}-[0-9]{6} +PASS"

step "Clean up"
ok cs destroy aws -y --env fips --purge --auto-approve
ok cs destroy vmware -y --env fipslab --purge --auto-approve
ok vault cs creds unset UBUNTU_PRO_TOKEN
