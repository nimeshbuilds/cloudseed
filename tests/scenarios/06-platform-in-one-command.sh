#!/usr/bin/env bash
# Scenario 06 - A production platform in one command (docs/scenarios/06-platform-in-one-command.md)
# Default: isolated; the cluster is only rendered, so the catalog commands that work offline run (list, info, plan,
# template) and the ones that need the cluster are checked to say so. CLOUDSEED_LIVE=1: installs basek8s on vmware-lab
# (built first when it does not exist - see lab_cluster in lib.sh), exposes the UIs, uninstalls and undoes.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 06-platform-in-one-command "A production platform in one command" vmware
need python3 terraform go

step "Before you start: the scenario 05 cluster"
if [[ "$SCN_LIVE" == "1" ]]; then
  lab_cluster
else
  ok cs setup vmware -y --env lab --var enable_kubernetes=true --dry-run
  ok cs env use vmware-lab
fi

step "1. Browse the catalog"
ok cs platform list
has "basek8s"
has "argocd"
ok cs platform list --charts
has "https://charts.jetstack.io"
ok cs platform info basek8s
has "group · basek8s"
ok cs platform info kube-prometheus-stack
has "monitoring"
ok cs explain platform
has "basek8s"

step "2. Plan before touching the cluster"
ok cs platform plan basek8s
has "Plan for vmware-lab \(vmware/rke2\)"
has "envoy-gateway +(install|already installed)"
has "metrics-server +built into the distro"

step "3. Install it"
if live "cs -y platform install basek8s --auto-approve (~15 min)"; then
  ok cs -y platform install basek8s --auto-approve
  has "Done"
else
  rc 1 cs -y platform install basek8s --auto-approve
  has "no Kubernetes cluster yet"
fi

step "4. Open the web UIs"
if live "cs platform status / cs platform ui / export the cluster CA"; then
  ok cs platform status
  has "argocd"
  ok cs -y platform ui --auto-approve
  has "https://argocd\.vmware-lab\.local"
  has "https://kube-prometheus-stack\.vmware-lab\.local"
  ok bash -c "cs kubectl -n cert-manager get secret cloudseed-root-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > cloudseed-ca.crt"
  check "cluster CA exported" grep -q "BEGIN CERTIFICATE" cloudseed-ca.crt
else
  rc 1 cs platform status
  rc 1 cs platform ui
  has "no Kubernetes cluster yet"
fi

step "5. Add a CI pipeline to your app repository"
ok cs platform template gitlab-ci
has "wrote .*\.gitlab-ci\.yml"
check ".gitlab-ci.yml has build, scan and deploy stages" grep -Eq "trivy|argocd" .gitlab-ci.yml

step "6. Remove an item, then undo it"
if live "cs platform uninstall sealed-secrets / cs undo"; then
  ok cs -y platform uninstall sealed-secrets --auto-approve
  has "sealed-secrets removed"
  ok cs undo --list
  has "platform uninstall sealed-secrets"
  ok cs -y undo --auto-approve
  ok cs platform status
  has "sealed-secrets"
else
  rc 1 cs -y platform uninstall sealed-secrets --auto-approve
  ok cs undo --list
  has "platform template gitlab-ci"
fi

step "Verify it worked"
if live "cs kubectl get pods -A / cs helm list -A / cs kubectl get gateway -A"; then
  ok cs kubectl get pods -A
  ok cs helm list -A
  has "kube-prometheus-stack|monitoring"
  ok cs kubectl get gateway -A
  has "cloudseed"
fi
ok cs explain platform basek8s
ok cs explain group security
has "istio|kyverno"

step "Clean up"
if [[ "$SCN_LIVE" == "1" ]]; then
  ok cs -y platform uninstall basek8s --auto-approve
else
  rc 1 cs platform uninstall basek8s
  ok cs destroy vmware -y --env lab --purge --auto-approve
  ok cs env clear
fi
