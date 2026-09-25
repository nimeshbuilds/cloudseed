#!/usr/bin/env bash
# Run the scenario scripts (all, or the ones named) and print a summary table.
#
#   tests/scenarios/run.sh                 every scenario: cloud ones with --dry-run, VMware ones as their dry-run
#                                          equivalent, 14/15 fully (local services in a throw-away home)
#   tests/scenarios/run.sh 02 05 14        only these (a number, a slug, or a file name)
#   tests/scenarios/run.sh -v 03           stream every command's output
#   tests/scenarios/run.sh --list          list the scenarios
#   CLOUDSEED_LIVE=1 tests/scenarios/run.sh 01 05 06
#                                          VMware scenarios for real (VMware Fusion Pro / Workstation Pro), with your
#                                          HOME and CLOUDSEED_HOME. The cluster scenarios (06-10, 13) share one
#                                          cluster, vmware-lab, built by 05 and destroyed at the end
#                                          (CLOUDSEED_KEEP=1 keeps it).
#
# Without CLOUDSEED_LIVE=1 nothing here reads or writes your real ~/.cloudseed, ~/.kube or MCP client configs: every
# script runs in its own temporary HOME and CLOUDSEED_HOME (tests/scenarios/lib.sh). Exit code: 1 when a scenario
# failed, else 0 (SKIP - a required tool is missing - is not a failure).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VERBOSE=0
PICK=()
for a in "$@"; do
  case "$a" in
    -v|--verbose) VERBOSE=1 ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --list)
      for f in "$HERE"/[0-9][0-9]-*.sh; do
        printf '%s  %s\n' "$(basename "$f" .sh)" "$(sed -n 's/^# Scenario [0-9]* - //p' "$f" | head -n 1)"
      done
      exit 0 ;;
    *) PICK+=("$a") ;;
  esac
done

ALL=()
for f in "$HERE"/[0-9][0-9]-*.sh; do ALL+=("$f"); done
SEL=()
if [[ ${#PICK[@]} -eq 0 ]]; then
  SEL=("${ALL[@]}")
else
  for p in "${PICK[@]}"; do
    p="${p%.sh}"; p="$(basename "$p")"
    [[ "$p" =~ ^[0-9]$ ]] && p="0$p"
    hit=""
    for f in "${ALL[@]}"; do
      b="$(basename "$f" .sh)"
      if [[ "$b" == "$p" || "$b" == "$p"-* || "${b#*-}" == "$p" ]]; then hit="$f"; fi
    done
    if [[ -z "$hit" ]]; then echo "no scenario matches '$p' (see: $0 --list)" >&2; exit 2; fi
    SEL+=("$hit")
  done
fi

LIVE="${CLOUDSEED_LIVE:-0}"
RUN="$(mktemp -d "${TMPDIR:-/tmp}/cs-scenarios-run-XXXXXX")"
mkdir -p "$RUN/logs"
export CLOUDSEED_SCENARIO_CACHE="${CLOUDSEED_SCENARIO_CACHE:-$RUN/cache}"
cleanup() {
  chmod -R u+w "$RUN" 2>/dev/null
  if [[ "${SCN_KEEP_LOGS:-0}" == "1" ]]; then echo "logs kept in $RUN/logs"; rm -rf "$RUN/cache"; else rm -rf "$RUN"; fi
}
trap cleanup EXIT

# live: the cluster scenarios share vmware-lab; keep it between them and destroy it once at the end. VMware's
# host-only network holds the VMs of one environment at a time, so 01 (vmware-first) and 11 (vmware-fipslab) go
# before the lab is built.
LAB_USERS=0
if [[ "$LIVE" == "1" ]]; then
  FIRST=(); REST=()
  for f in "${SEL[@]}"; do
    case "$(basename "$f")" in 01-*|11-*) FIRST+=("$f") ;; *) REST+=("$f") ;; esac
  done
  SEL=()
  [[ ${#FIRST[@]} -gt 0 ]] && SEL+=("${FIRST[@]}")
  [[ ${#REST[@]} -gt 0 ]] && SEL+=("${REST[@]}")
  for f in "${SEL[@]}"; do
    case "$(basename "$f")" in 05-*|06-*|07-*|08-*|09-*|10-*|13-*) LAB_USERS=$((LAB_USERS + 1)) ;; esac
  done
  echo "CLOUDSEED_LIVE=1: VMware scenarios run for real with CLOUDSEED_HOME=${CLOUDSEED_HOME:-$HOME/.cloudseed}"
fi

ROWS=()
FAILED=0
for f in "${SEL[@]}"; do
  name="$(basename "$f" .sh)"
  log="$RUN/logs/$name.log"
  keep="${CLOUDSEED_KEEP:-0}"
  case "$name" in 05-*|06-*|07-*|08-*|09-*|10-*|13-*) [[ "$LIVE" == "1" && $LAB_USERS -gt 1 ]] && keep=1 ;; esac
  echo ">> $name"
  start=$(date +%s)
  if [[ "$VERBOSE" == "1" ]]; then
    CLOUDSEED_KEEP="$keep" SCN_VERBOSE=1 bash "$f" 2>&1 | tee "$log"
  else
    CLOUDSEED_KEEP="$keep" bash "$f" >"$log" 2>&1
  fi
  line="$(grep -E '^RESULT ' "$log" | tail -n 1)"
  secs=$(( $(date +%s) - start ))
  if [[ -z "$line" ]]; then
    line="RESULT $name FAIL mode=? checks=0 skipped=0 seconds=$secs"
  fi
  result="$(awk '{print $3}' <<<"$line")"
  mode="$(sed -n 's/.* mode=\([^ ]*\).*/\1/p' <<<"$line")"
  checks="$(sed -n 's/.* checks=\([0-9]*\).*/\1/p' <<<"$line")"
  skipped="$(sed -n 's/.* skipped=\([0-9]*\).*/\1/p' <<<"$line")"
  ROWS+=("$(printf '%-30s %-8s %-5s %6s %8s %6ss' "$name" "$mode" "$result" "$checks" "$skipped" "$secs")")
  if [[ "$result" == "FAIL" ]]; then
    FAILED=$((FAILED + 1))
    if [[ "$VERBOSE" != "1" ]]; then
      echo "   FAILED - last lines of $name:"
      tail -n 30 "$log" | sed 's/^/   | /'
    fi
  else
    echo "   $result"
  fi
done

if [[ "$LIVE" == "1" && $LAB_USERS -gt 1 && "${CLOUDSEED_KEEP:-0}" != "1" ]]; then
  echo ">> destroying vmware-lab (shared by the cluster scenarios; CLOUDSEED_KEEP=1 keeps it)"
  # the short TMPDIR lib.sh gives the scenarios: Terraform's provider sockets live there (a ~104-byte path limit)
  dtmp="${TMPDIR:-/tmp}"; [[ ${#dtmp} -gt 60 ]] && dtmp=/tmp
  TMPDIR="$dtmp" "$REPO/bin/cloudseed" destroy vmware -y --env lab --purge --auto-approve </dev/null >"$RUN/logs/lab-destroy.log" 2>&1 \
    || { echo "   destroy failed - see: cloudseed troubleshoot vmware --env lab"; FAILED=$((FAILED + 1)); }
fi

echo
printf '%-30s %-8s %-5s %6s %8s %7s\n' "SCENARIO" "MODE" "RESULT" "CHECKS" "SKIPPED" "TIME"
printf '%-30s %-8s %-5s %6s %8s %7s\n' "------------------------------" "--------" "-----" "------" "--------" "-------"
for r in "${ROWS[@]}"; do echo "$r"; done
echo
echo "SKIPPED = live or credentialed steps not run in this mode (each script lists them); CLOUDSEED_LIVE=1 runs the VMware ones."
if [[ $FAILED -gt 0 ]]; then
  echo "$FAILED scenario(s) failed. Re-run one with: $0 -v <number>   (SCN_KEEP_LOGS=1 keeps every log)"
  exit 1
fi
exit 0
