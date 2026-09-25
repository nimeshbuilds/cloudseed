#!/usr/bin/env bash
# Scenario 03 - GCP landing zone with a private GKE cluster (docs/scenarios/03-gcp-private-gke.md)
# Cloud scenario: --dry-run in a throw-away home; nothing reaches Google Cloud. Cluster commands are checked to stop
# cleanly before the cluster exists; the apply and the live cluster steps are listed as skipped.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 03-gcp-private-gke "GCP landing zone with a private GKE cluster" cloud
need python3 terraform

step "1. Install gcloud and log in"
skip "cs install gcloud gke-gcloud-auth-plugin (installs software)"
skip "gcloud auth login / gcloud auth application-default login (a Google account)"
# doctor for a named cloud exits 1 while that cloud is not ready (no credentials here): the output is the check
any cs doctor gcp
has "Google Cloud"

step "2. Read what you are about to build"
ok cs help gcp
has "cloudseed on Google Cloud"
ok cs help variables gcp
has "enable_os_login"
ok cs explain kubernetes
has "GKE"

step "3. Dry run with OS Login and GKE"
ok cs setup gcp -y --env prod --project-id my-gcp-project --region europe-west1 --allow-ip 203.0.113.7 --var enable_os_login=true --var enable_kubernetes=true --dry-run
has "Environment gcp-prod"
has "zone +europe-west1-b"
has "enable_os_login +true"
has "enable_kubernetes +true"
has "Dry run complete"
check "both roots validated" test "$(grep -c 'Success! The configuration is valid' "$SCN_OUT")" -eq 2

step "4. Check the monthly estimate"
ok cs finops estimate gcp --env prod
has "GKE cluster fee"
has "total / month"

step "5. Create it"
skip "cs setup gcp --env prod ... (apply: a GCP project with billing)"

step "6. Talk to the private cluster"
ok cs k8s info gcp --env prod
has "enabled in the configuration but has not been created yet"
rc 1 cs kubectl gcp --env prod get nodes -o wide
has "gcloud|not created yet"
rc 1 cs k8s kubeconfig gcp --env prod
has "gcloud|not created yet"
rc 1 cs k8s tunnel gcp --env prod
has "gcloud|not created yet"
ok cs k8s untunnel gcp --env prod
has "No tunnel running"

step "7. SSH and scale"
rc 1 cs ssh gcp --env prod
has "gcloud|not been applied yet"
rc 1 cs node list gcp --env prod
rc 1 cs node scale gcp --env prod --count 3 --max 5
skip "cs ssh / cs node list / cs node scale on a real GKE cluster"

step "Verify it worked"
ok cs status gcp --env prod
has "Environment gcp-prod"
ok cs troubleshoot gcp --env prod
has "Troubleshooting gcp-prod"
ok cs explain target gcp
has "Google Cloud|gcp"

step "Clean up"
ok cs destroy gcp -y --env prod --purge-state --purge --auto-approve
has "Removed .*gcp-prod"
