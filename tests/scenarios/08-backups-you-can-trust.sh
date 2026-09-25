#!/usr/bin/env bash
# Scenario 08 - Backups you can trust (docs/scenarios/08-backups-you-can-trust.md)
# Default: isolated; the resilience group is planned offline for the local cluster and for an EKS environment (cloud
# prerequisites), and every `cs dr` command is checked to say the cluster is not created yet. CLOUDSEED_LIVE=1: Velero
# on vmware-lab, backup / delete / restore of the shop namespace, the DR drill, a schedule, undo, uninstall.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 08-backups-you-can-trust "Backups you can trust" vmware
need python3 terraform go

ensure_shop() {   # the scenario 05 workload, when the cluster was built without it
  if ! cs kubectl get namespace shop </dev/null >/dev/null 2>&1; then
    ok cs kubectl create namespace shop
    ok cs kubectl -n shop create deployment web --image=nginxinc/nginx-unprivileged:1.27-alpine --replicas=3 --port=8080
    ok cs kubectl -n shop expose deployment web --port=8080
  fi
  ok cs kubectl -n shop rollout status deployment/web --timeout=180s
}

step "Before you start: the scenario 05 cluster and its shop app"
if [[ "$SCN_LIVE" == "1" ]]; then
  lab_cluster
  ensure_shop
else
  ok cs setup vmware -y --env lab --var enable_kubernetes=true --dry-run
  ok cs env use vmware-lab
fi

step "1. Understand the moving parts"
ok cs explain dr
has "Velero"
ok cs help dr
has "cs dr test"
ok cs platform info resilience
has "velero"

step "2. Plan and install the resilience group"
ok cs platform plan resilience
has "minio +install"
has "velero +install"
ok cs setup aws -y --env eks --allow-ip 203.0.113.7 --var enable_kubernetes=true --dry-run
ok cs platform plan resilience aws --env eks
has "cloud prerequisites 'velero' \(identity, storage, tags\) are applied to the aws stack first"
ok cs destroy aws -y --env eks --purge --auto-approve
if live "cs -y platform install resilience --auto-approve"; then
  ok cs -y platform install resilience --auto-approve
  has "velero installed"
else
  rc 1 cs -y platform install resilience --auto-approve
fi

step "3. Back up, break, restore"
if live "cs dr backup before-change / kubectl delete namespace shop / cs dr restore before-change"; then
  ok cs dr status
  ok cs -y dr backup before-change --namespaces shop --auto-approve
  has "Backup before-change Completed"
  ok cs dr backups
  has "before-change"
  ok cs kubectl delete namespace shop
  ok cs kubectl wait --for=delete namespace/shop --timeout=180s
  ok cs -y dr restore before-change --namespaces shop --auto-approve
  has "Restore before-change(-restore-[0-9]+)? Completed"
  ok cs kubectl -n shop rollout status deployment/web --timeout=180s
  ok cs kubectl -n shop get pods
  has "web-.* +1/1 +Running"
  ok cs dr describe backup before-change --details
  has "Completed"
  ok cs dr logs backup before-change
else
  rc 1 cs dr status
  has "no Kubernetes cluster yet"
  rc 1 cs dr backup before-change --namespaces shop
  rc 1 cs dr backups
  rc 1 cs dr restore before-change --namespaces shop
  rc 1 cs dr describe backup before-change --details
  rc 1 cs dr logs backup before-change
fi

step "4. Prove that restores work"
if live "cs dr test (automated drill)"; then
  ok cs -y dr test --auto-approve
  has "PASS - backup and restore are trustworthy"
  check "drill report saved" bash -c "ls \"${CLOUDSEED_HOME:-$HOME/.cloudseed}\"/envs/vmware-lab/dr/drill-*.md"
else
  rc 1 cs dr test
  has "no Kubernetes cluster yet"
fi

step "5. Schedule nightly backups"
if live "cs dr schedule nightly --cron \"0 2 * * *\" --ttl 720h"; then
  ok cs -y dr schedule nightly --cron "0 2 * * *" --ttl 720h --auto-approve
  has "Schedule nightly"
  ok cs dr status
  has "nightly"
else
  rc 1 cs dr schedule nightly --cron "0 2 * * *" --ttl 720h
fi

step "Verify it worked"
if [[ "$SCN_LIVE" == "1" ]]; then
  ok cs dr backups
  has "before-change"
fi
ok cs explain prereqs
has "velero|Velero"

step "Clean up"
if [[ "$SCN_LIVE" == "1" ]]; then
  ok cs undo --list
  has "dr schedule nightly"
  ok cs -y undo --auto-approve
  ok cs -y platform uninstall resilience --auto-approve
else
  ok cs destroy vmware -y --env lab --purge --auto-approve
  ok cs env clear
fi
