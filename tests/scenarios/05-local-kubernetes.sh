#!/usr/bin/env bash
# Scenario 05 - Kubernetes on your laptop (docs/scenarios/05-local-kubernetes.md)
# Default: isolated dry run of the RKE2 and kubeadm clusters; cluster commands are checked to say "not created yet".
# CLOUDSEED_LIVE=1: builds vmware-lab with RKE2 (1 control plane + 2 workers) and runs everything against it; the
# cluster is destroyed at the end unless CLOUDSEED_KEEP=1 (run.sh keeps it for scenarios 06-10 and 13).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 05-local-kubernetes "Kubernetes on your laptop" vmware
need python3 terraform go

step "1. Install the Kubernetes tools"
ok cs doctor vmware
has "VMware Fusion / Workstation"
skip "cs install kubernetes / cs install k9s (installs software)"

step "2. Preview the cluster"
ok cs help variables vmware
has "kubernetes_distro"
ok cs setup vmware -y --env lab --var enable_kubernetes=true --dry-run
has "kubernetes_distro +rke2"
has "kubernetes_workers +2"
has "Dry run complete"

step "3. Build the cluster"
ok cs setup vmware -y --env lab --var enable_kubernetes=true --var kubernetes_distro=kubeadm --dry-run
has "kubernetes_distro +kubeadm"
has "Dry run complete"
has "saved configuration of vmware-lab is not changed|vmware-lab itself is unchanged"
if live "cs setup vmware -y --env lab --var enable_kubernetes=true --auto-approve (RKE2 cluster, ~25 min)"; then
  [[ "${CLOUDSEED_KEEP:-0}" == "1" ]] || on_exit cs destroy vmware -y --env lab --purge --auto-approve
  ok cs setup vmware -y --env lab --var enable_kubernetes=true --auto-approve
  has "vmware-lab is ready"
fi

step "4. Make it the current environment"
ok cs env use vmware-lab
has "Current environment: vmware-lab"
ok cs env
has "vmware-lab +◀ current"

step "5. Connect your tools"
ok cs k8s info vmware --env lab
if [[ "$SCN_LIVE" == "1" ]]; then
  has "kubeconfig +cs k8s kubeconfig vmware --env lab"
  ok cs k8s kubeconfig vmware --env lab
  ok kubectl get nodes -o wide
  has "cloudseed-lab-cp1 +Ready"
  has "cloudseed-lab-wk2 +Ready"
  ok cs kubectl get pods -A
  ok cs helm list -A
  skip "cs k9s (an interactive terminal UI)"
else
  has "not been created yet"
  rc 1 cs k8s kubeconfig vmware --env lab
  has "not created yet"
  rc 1 cs kubectl get pods -A
  has "no Kubernetes cluster yet"
  rc 1 cs helm list -A
  rc 1 cs k9s
  has "no Kubernetes cluster yet"
fi

step "6. Run a first workload"
if live "cs kubectl create namespace shop / create deployment web / expose / rollout status"; then
  ok cs kubectl create namespace shop
  ok cs kubectl -n shop create deployment web --image=nginxinc/nginx-unprivileged:1.27-alpine --replicas=3 --port=8080
  ok cs kubectl -n shop expose deployment web --port=8080
  ok cs kubectl -n shop rollout status deployment/web --timeout=180s
  ok cs kubectl -n shop get pods -o wide
  has "web-.* +1/1 +Running"
else
  rc 1 cs kubectl -n shop create deployment web --image=nginxinc/nginx-unprivileged:1.27-alpine --replicas=3 --port=8080
fi

step "Verify it worked"
if [[ "$SCN_LIVE" == "1" ]]; then
  ok cs node list
  has "cloudseed-lab-wk1"
else
  rc 1 cs node list
  has "no Kubernetes cluster yet"
fi
ok cs troubleshoot vmware --env lab
has "Troubleshooting vmware-lab"
ok cs explain kubernetes
ok cs help k8s
has "kubeconfig"

step "Clean up"
if [[ "$SCN_LIVE" == "1" ]]; then
  if [[ "${CLOUDSEED_KEEP:-0}" != "1" ]]; then
    ok cs destroy vmware -y --env lab --purge --auto-approve
    ok cs env clear
  else
    _scn_say "   (CLOUDSEED_KEEP=1: vmware-lab and the shop workload stay for scenarios 06-10 and 13)"
  fi
else
  ok cs destroy vmware --env lab
  ok cs env clear
  has "Current environment cleared"
  ok cs destroy vmware -y --env lab --purge --auto-approve
fi
