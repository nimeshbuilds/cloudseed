#!/usr/bin/env bash
# Scenario 04 - Azure landing zone with private AKS (docs/scenarios/04-azure-private-aks.md)
# Cloud scenario: --dry-run in a throw-away home; nothing reaches Azure. Cluster, node and scan commands are checked to
# stop cleanly before anything exists; the apply and the live steps are listed as skipped.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 04-azure-private-aks "Azure landing zone with private AKS" cloud
need python3 terraform

step "1. Install az and log in"
skip "cs install az / az login / az account show (an Azure subscription)"
# doctor for a named cloud exits 1 while that cloud is not ready (no credentials here): the output is the check
any cs doctor azure
has "Microsoft Azure"

step "2. Read the Azure reference"
ok cs help azure
has "Azure"
ok cs help variables azure
has "enable_defender"

step "3. Dry run with AKS and Defender"
ok cs setup azure -y --env prod --subscription-id 00000000-0000-0000-0000-000000000000 --region westeurope --allow-ip 203.0.113.7 --var enable_kubernetes=true --var enable_defender=true --dry-run
has "Environment azure-prod"
has "enable_defender +true"
has "kubernetes_public_endpoint +false"
has "Dry run complete"
check "both roots validated" test "$(grep -c 'Success! The configuration is valid' "$SCN_OUT")" -eq 2

step "4. Check the monthly estimate"
ok cs finops estimate azure --env prod
has "Defender for Servers"
has "total / month"

step "5. Create it"
skip "cs setup azure --env prod ... (apply: an Azure subscription)"

step "6. Use the private cluster"
ok cs k8s info azure --env prod
has "not been created yet"
rc 1 cs kubectl azure --env prod get nodes
has "not created yet"
rc 1 cs helm azure --env prod list -A
has "not created yet"

step "7. Resize the node pool"
rc 1 cs node list azure --env prod
has "not created yet"
rc 1 cs node add azure --env prod --count 1
rc 1 cs node scale azure --env prod --count 3 --max 5
rc 1 cs node remove aks-default-30114873-vmss000002 azure --env prod
has "not created yet"
skip "cs node add|scale|remove on a real AKS pool"

step "Verify it worked"
ok cs status azure --env prod
has "Environment azure-prod"
rc 2 cs scan cloud azure --env prod
has "prowler needs Azure credentials"
skip "cs scan cloud azure --env prod (prowler CIS against a real subscription)"
ok cs explain target azure
ok cs explain scan
has "kube-bench"

step "Clean up"
ok cs destroy azure -y --env prod --purge-state --purge --auto-approve
has "Removed .*azure-prod"
