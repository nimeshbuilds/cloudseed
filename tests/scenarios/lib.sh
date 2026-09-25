# shellcheck shell=bash
# Shared helpers for the scenario scripts (tests/scenarios/NN-*.sh). Source it, do not run it.
#
# Every scenario script runs the exact commands of its page in docs/scenarios/ and checks their exit codes and output.
#
# Modes
#   default            isolated: a throw-away HOME and CLOUDSEED_HOME under $TMPDIR, cloud credentials unset.
#                      Cloud scenarios (AWS / GCP / Azure) run with --dry-run (Terraform render + validate); VMware
#                      scenarios run their dry-run equivalent and list the live steps they skipped.
#   CLOUDSEED_LIVE=1   VMware scenarios build real VMs with your own HOME and CLOUDSEED_HOME (default ~/.cloudseed),
#                      exactly as the page shows, and destroy what they created on exit (CLOUDSEED_KEEP=1 keeps it).
#                      Cloud scenarios still use --dry-run; scenarios 14 and 15 always stay isolated (they start
#                      their own MCP server and web console under the throw-away home).
#
# Other knobs
#   SCN_VERBOSE=1               stream every command's output (default in live mode)
#   CLOUDSEED_SCENARIO_CACHE    directory for shared download caches (Terraform providers, Go modules); run.sh sets
#                               one per run so providers are downloaded once. Default: inside the throw-away dir.
#   SCN_KEEP_TMP=1              keep the throw-away directory for inspection
#   SCN_UI_PORT / SCN_MCP_PORT  ports for scenario 15 / 14 (defaults 7985 / 7984)

set -euo pipefail

SCN_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCN_NAME=""
SCN_TITLE=""
SCN_KIND=""          # cloud | vmware | local
SCN_MODE=""          # dry-run | live | local
SCN_LIVE=0
SCN_CHECKS=0
SCN_SKIPPED=()
SCN_STEP="(setup)"
SCN_CLEANUPS=()
SCN_START=$(date +%s)
SCN_RESULT=""
SCN_TMP=""
SCN_OUT=""
SCN_RC=0

_scn_say() { printf '%s\n' "$*"; }
_scn_err() { printf '%s\n' "$*" >&2; }

# scn_begin NN-slug "Title" cloud|vmware|local
scn_begin() {
  SCN_NAME="$1"; SCN_TITLE="$2"; SCN_KIND="$3"
  if [[ "${CLOUDSEED_LIVE:-0}" == "1" && "$SCN_KIND" == "vmware" ]]; then
    SCN_LIVE=1; SCN_MODE="live"
  elif [[ "$SCN_KIND" == "local" ]]; then
    SCN_MODE="local"
  else
    SCN_MODE="dry-run"
  fi
  : "${SCN_VERBOSE:=$SCN_LIVE}"

  # Terraform talks to its providers over unix sockets in $TMPDIR, and a socket path is limited to ~104 bytes:
  # a long TMPDIR makes every provider fail to start
  local tmp="${TMPDIR:-/tmp}"
  if [[ ${#tmp} -gt 60 ]]; then export TMPDIR=/tmp; fi
  SCN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/cs-scenario-${SCN_NAME%%-*}-XXXXXX")"
  SCN_OUT="$SCN_TMP/last-output.txt"
  local cache="${CLOUDSEED_SCENARIO_CACHE:-$SCN_TMP/cache}"
  mkdir -p "$cache/terraform-plugins" "$cache/go-mod" "$cache/go-build" "$cache/go-path" "$SCN_TMP/bin" "$SCN_TMP/work"
  trap _scn_finish EXIT
  trap 'exit 130' INT TERM

  if [[ "$SCN_LIVE" != "1" ]]; then
    # isolated: nothing of yours is read or written - not ~/.cloudseed, not ~/.kube, not your MCP client configs
    _scn_scrub_env
    export HOME="$SCN_TMP/home"
    export CLOUDSEED_HOME="$SCN_TMP/cloudseed"
    mkdir -p "$HOME"
  fi
  _scn_guard_home

  # Terraform providers and Go modules are downloaded once per cache, never into your own caches in isolated mode
  export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$cache/terraform-plugins}"
  if [[ "$SCN_LIVE" != "1" ]]; then
    export GOMODCACHE="$cache/go-mod" GOCACHE="$cache/go-build" GOPATH="$cache/go-path"
  fi
  export GOFLAGS="${GOFLAGS:+$GOFLAGS }-modcacherw"   # a read-only module cache would make the cleanup fail
  export NO_COLOR=1 COLUMNS=120 PYTHONDONTWRITEBYTECODE=1

  # `cs` and `cloudseed` are this checkout's, whatever else is on PATH
  ln -s "$SCN_REPO/bin/cloudseed" "$SCN_TMP/bin/cloudseed"
  ln -s "$SCN_REPO/bin/cloudseed" "$SCN_TMP/bin/cs"
  export PATH="$SCN_TMP/bin:$PATH"
  cd "$SCN_TMP/work"

  _scn_say "== Scenario $SCN_NAME - $SCN_TITLE  [$SCN_MODE]"
  _scn_say "   CLOUDSEED_HOME=${CLOUDSEED_HOME:-$HOME/.cloudseed}"
}

# Unset everything that could point a command at a real account or change how cloudseed behaves.
_scn_scrub_env() {
  local v
  for v in $(compgen -e); do
    case "$v" in
      CLOUDSEED_LIVE|CLOUDSEED_KEEP|CLOUDSEED_SCENARIO_*) ;;
      AWS_*|GOOGLE_*|CLOUDSDK_*|GCLOUD_*|ARM_*|AZURE_*|ANTHROPIC_*|OPENAI_*|GEMINI_*|GROK_*|XAI_*|CLAUDE_*|\
      UBUNTU_PRO_TOKEN|TS_AUTHKEY|GITLAB_*|DATABRICKS_*|SNOWFLAKE_*|KUBECONFIG|VMREST_*|VMWARE_HOME|CLOUDSEED_*|\
      MCP_TOOL_TIMEOUT|XDG_CONFIG_HOME|XDG_DATA_HOME|XDG_CACHE_HOME)
        unset "$v" ;;
    esac
  done
}

# Refuse to run an isolated scenario against the real cloudseed home.
_scn_guard_home() {
  [[ "$SCN_LIVE" == "1" ]] && return 0
  local real
  real="$(python3 -c 'import os,pwd; print(os.path.realpath(os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".cloudseed")))')"
  local mine
  mine="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${CLOUDSEED_HOME:-$HOME/.cloudseed}")"
  if [[ "$mine" == "$real" || "$mine" == "$real"/* ]]; then
    _scn_err "refusing to run: CLOUDSEED_HOME points at your real ~/.cloudseed ($real) outside live mode"
    exit 2
  fi
}

# need TOOL...: skip the whole scenario (not a failure) when a required tool is missing
need() {
  local t
  for t in "$@"; do
    if ! command -v "$t" >/dev/null 2>&1; then
      SCN_RESULT="SKIP"
      _scn_say "SKIP: $t is not installed (this scenario needs: $*)"
      exit 0
    fi
  done
}

step() { SCN_STEP="$*"; _scn_say ""; _scn_say "-- $*"; }

# on_exit CMD...: run CMD when the script ends (last registered first), whatever happened
on_exit() { SCN_CLEANUPS+=("$(printf '%q ' "$@")"); }

_scn_run() {
  local shown
  shown="$(printf '%q ' "$@")"
  _scn_say "   \$ ${shown% }"
  set +e
  if [[ "${SCN_VERBOSE:-0}" == "1" ]]; then
    "$@" </dev/null 2>&1 | tee "$SCN_OUT"
    SCN_RC=${PIPESTATUS[0]}
  else
    "$@" </dev/null >"$SCN_OUT" 2>&1
    SCN_RC=$?
  fi
  set -e
}

_scn_fail() {
  _scn_err "   FAILED: $*"
  _scn_err "   --- last output ($SCN_OUT) ---"
  tail -n 40 "$SCN_OUT" 2>/dev/null | sed 's/^/   | /' >&2 || true
  return 1
}

# ok CMD...: run CMD, expect exit code 0
ok() {
  _scn_run "$@"
  SCN_CHECKS=$((SCN_CHECKS + 1))
  [[ "$SCN_RC" == "0" ]] || _scn_fail "expected exit 0, got $SCN_RC"
}

# rc N CMD...: run CMD, expect exit code N (e.g. 3 = a plan waits for approval, 2 = refused)
rc() {
  local want="$1"; shift
  _scn_run "$@"
  SCN_CHECKS=$((SCN_CHECKS + 1))
  [[ "$SCN_RC" == "$want" ]] || _scn_fail "expected exit $want, got $SCN_RC"
}

# any CMD...: run CMD, accept any exit code (the output checks that follow decide)
any() {
  _scn_run "$@"
}

# has REGEX: the last command's output matches (extended regex)
has() {
  SCN_CHECKS=$((SCN_CHECKS + 1))
  grep -Eq -- "$1" "$SCN_OUT" || _scn_fail "output does not match: $1"
}

# hasnt REGEX: the last command's output does not match
hasnt() {
  SCN_CHECKS=$((SCN_CHECKS + 1))
  if grep -Eq -- "$1" "$SCN_OUT"; then _scn_fail "output unexpectedly matches: $1"; fi
}

# check "what" CMD...: a plain shell check (test -f ..., grep ...) counted like the others
check() {
  local what="$1"; shift
  SCN_CHECKS=$((SCN_CHECKS + 1))
  if ! "$@" >/dev/null 2>&1; then
    _scn_err "   FAILED: $what"
    return 1
  fi
  _scn_say "   ok: $what"
}

# live "what": true in live mode; otherwise records the step as skipped (the lead / you run it on VMware)
live() {
  if [[ "$SCN_LIVE" == "1" ]]; then return 0; fi
  SCN_SKIPPED+=("$*")
  _scn_say "   (live only, skipped: $*)"
  return 1
}

# skip "what": a step that needs something this run does not have (cloud credentials, a token ...)
skip() {
  SCN_SKIPPED+=("$*")
  _scn_say "   (skipped: $*)"
}

# vault CMD...: run a global-state command (credential vault, global undo) against a throw-away cloudseed home in live
# mode, so a live run never changes or clears your real credential vault or your global undo history.
vault() {
  if [[ "$SCN_LIVE" == "1" ]]; then
    mkdir -p "$SCN_TMP/vault-home"
    CLOUDSEED_HOME="$SCN_TMP/vault-home" "$@"
  else
    "$@"
  fi
}

# The cluster every platform scenario (06-10, 13) works on: the one scenario 05 builds. Live mode only.
# Reuses vmware-lab when it already has a cluster; otherwise builds it and destroys it on exit (unless CLOUDSEED_KEEP=1).
lab_cluster() {
  if cs k8s info vmware --env lab </dev/null 2>/dev/null | grep -Eq "kubeconfig +cs k8s kubeconfig vmware --env lab"; then
    _scn_say "   using the existing cluster vmware-lab"
  else
    ok cs setup vmware -y --env lab --var enable_kubernetes=true --auto-approve
    if [[ "${CLOUDSEED_KEEP:-0}" != "1" ]]; then
      on_exit cs destroy vmware -y --env lab --purge --auto-approve
    fi
  fi
  ok cs env use vmware-lab
  ok cs k8s kubeconfig vmware --env lab
}

_scn_finish() {
  local code=$?
  set +e
  local i
  for ((i = ${#SCN_CLEANUPS[@]} - 1; i >= 0; i--)); do
    _scn_say "   (cleanup) \$ ${SCN_CLEANUPS[$i]}"
    if [[ "${SCN_VERBOSE:-0}" == "1" ]]; then
      eval "${SCN_CLEANUPS[$i]}" </dev/null 2>&1 | tail -n 5
    else
      eval "${SCN_CLEANUPS[$i]}" </dev/null >/dev/null 2>&1
    fi
  done
  cd /
  if [[ -z "$SCN_RESULT" ]]; then
    if [[ "$code" == "0" ]]; then SCN_RESULT="PASS"; else SCN_RESULT="FAIL"; fi
  fi
  if [[ -n "$SCN_TMP" && "${SCN_KEEP_TMP:-0}" != "1" ]]; then
    chmod -R u+w "$SCN_TMP" 2>/dev/null
    rm -rf "$SCN_TMP" 2>/dev/null
  fi
  local secs=$(( $(date +%s) - SCN_START ))
  _scn_say ""
  if [[ ${#SCN_SKIPPED[@]} -gt 0 ]]; then
    _scn_say "   live / credentialed steps not run here:"
    local s
    for s in "${SCN_SKIPPED[@]}"; do _scn_say "     - $s"; done
  fi
  [[ "$SCN_RESULT" == "FAIL" ]] && _scn_say "   failed at step: $SCN_STEP"
  _scn_say "RESULT $SCN_NAME $SCN_RESULT mode=$SCN_MODE checks=$SCN_CHECKS skipped=${#SCN_SKIPPED[@]} seconds=$secs"
  [[ "$SCN_RESULT" == "FAIL" ]] && exit 1
  exit 0
}
