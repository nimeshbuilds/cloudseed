#!/usr/bin/env bash
# Scenario 09 - Chaos engineering with verdicts (docs/scenarios/09-chaos-engineering.md)
# Default: isolated; the experiments are listed and the chaos group planned offline, and the run commands are checked to
# say the cluster is not created yet. CLOUDSEED_LIVE=1: the basic suite against the canary and two experiments against
# shop/web on vmware-lab, then report, status, stop and uninstall.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 09-chaos-engineering "Chaos engineering with verdicts" vmware
need python3 terraform go

ensure_shop() {
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

step "1. See the experiments and their hypotheses"
ok cs chaos list
has "pod-kill"
has "network-partition"
has "time-skew"
ok cs explain chaos
has "steady|hypothesis|availability"
ok cs platform plan chaos
has "chaos-mesh +install"

step "2. Run the basic suite against a canary"
if live "cs -y chaos run basic --auto-approve (installs Chaos Mesh, ~5 min)"; then
  ok cs -y chaos run basic --auto-approve
  has "PASS - every experiment held its steady-state hypothesis"
else
  rc 1 cs chaos run
  rc 1 cs -y chaos run basic --auto-approve
  has "no Kubernetes cluster yet"
fi

step "3. Target your own workload"
if live "cs chaos run network-delay pod-kill --target shop/web:8080 --duration 60s"; then
  ok cs -y chaos run network-delay pod-kill --target shop/web:8080 --duration 60s --auto-approve
  has "shop/web"
  ok cs chaos report
  has "Chaos results"
else
  rc 1 cs chaos run network-delay pod-kill --target shop/web:8080 --duration 60s
  rc 1 cs chaos report
  has "No chaos report yet"
fi

step "4. Watch and stop"
if live "cs chaos status / cs chaos stop"; then
  ok cs chaos status
  ok cs chaos stop
  has "deleted"
else
  rc 1 cs chaos status
  rc 1 cs chaos stop
fi

step "Verify it worked"
if [[ "$SCN_LIVE" == "1" ]]; then
  check "chaos reports saved" bash -c "ls \"${CLOUDSEED_HOME:-$HOME/.cloudseed}\"/envs/vmware-lab/chaos/report-*.md"
  ok cs kubectl -n shop rollout status deployment/web --timeout=180s
fi

step "Clean up"
if [[ "$SCN_LIVE" == "1" ]]; then
  ok cs chaos stop
  ok cs -y platform uninstall chaos --auto-approve
else
  rc 1 cs platform uninstall chaos
  ok cs destroy vmware -y --env lab --purge --auto-approve
  ok cs env clear
fi
