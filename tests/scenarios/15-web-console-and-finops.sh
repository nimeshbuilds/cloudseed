#!/usr/bin/env bash
# Scenario 15 - Web console and FinOps (docs/scenarios/15-web-console-and-finops.md)
# Local scenario, always in a throw-away HOME and CLOUDSEED_HOME: starts a real console on SCN_UI_PORT (default 7985),
# drives it through its HTTP API like the browser does (the wizard's dry run, an estimate, Activity), checks the token
# and Origin protection and the audit trail, runs the FinOps commands, manages and removes the console.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 15-web-console-and-finops "Web console and FinOps" local
need python3 curl terraform
PORT="${SCN_UI_PORT:-7985}"
PORT2="${SCN_UI_PORT2:-7986}"
URL="http://127.0.0.1:$PORT"
on_exit cs disable ui
on_exit cs destroy aws -y --env web --purge --auto-approve

# api METHOD PATH [JSON]: call the console API with the token, like the browser's app does
api() {
  local token; token="$(cat "$CLOUDSEED_HOME/ui/token")"
  if [[ $# -ge 3 ]]; then
    curl -s -X "$1" -H "X-CS-Token: $token" -H "Content-Type: application/json" -d "$3" "$URL$2"
  else
    curl -s -X "$1" -H "X-CS-Token: $token" "$URL$2"
  fi
}
# job ACTION ARGS-JSON: start a console job and wait for it; prints its output, exits with its exit code
job() {
  local started id
  started="$(api POST /api/run "{\"action\": \"$1\", \"args\": $2}")"
  id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["job"])' <<<"$started")"
  local i
  for i in $(seq 1 300); do
    local st; st="$(api GET "/api/jobs/$id")"
    if python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("rc") is not None else 1)' <<<"$st"; then
      python3 -c 'import json,sys; d=json.load(sys.stdin); print("\n".join(d.get("lines") or [])); sys.exit(d["rc"])' <<<"$st"
      return $?
    fi
    sleep 1
  done
  echo "job $id did not finish"; return 124
}

# Keep the isolated console a background process, without a host login item.
mkdir -p "$CLOUDSEED_HOME/ui"
printf '%s\n' '{"service":"background"}' > "$CLOUDSEED_HOME/ui/server.json"

step "1. Start the console"
ok cs enable ui --no-open --port "$PORT"
has "cloudseed console is up: $URL/"
ok cs ui token
has "^$URL/\?token=[A-Za-z0-9_-]{20,}$"
ok cs ui status
has "Health +running"
TOKEN="$(cat "$CLOUDSEED_HOME/ui/token")"
ok curl -s -o /dev/null -w "%{http_code}" "$URL/?token=$TOKEN"
has "^200$"
ok curl -s -o /dev/null -w "%{http_code}" "$URL/api/state"
has "^401$"
ok curl -s -o /dev/null -w "%{http_code}" -X POST -H "X-CS-Token: $TOKEN" -H "Origin: http://evil.example" -d "{}" "$URL/api/run"
has "^403$"
ok curl -s "$URL/health"
has '"server": "cloudseed-ui"'

step "2. Create an environment with the wizard (the console's API, like the browser)"
ok job cloudseed_setup '{"cloud": "aws", "env": "web", "region": "us-west-2", "allow_ip": "203.0.113.7", "dry_run": true}'
has "Dry run complete"
ok cs setup aws -y --env web --region us-west-2 --allow-ip 203.0.113.7 --dry-run
has "aws-web itself is unchanged"
ok api GET /api/state
has '"aws-web"'

step "3. Explore the rest of the console"
ok api GET /api/actions
has "cloudseed_platform"
ok api GET /api/jobs
has '"label"'
rc 3 job cloudseed_scan '{"kind": "architecture", "cloud": "aws", "env": "web", "profile": "lab", "max_age_days": 30}'
has "Well-Architected screening"
has "INCOMPLETE"
ok api GET '/api/reports?env=aws-web'
has '"architecture"'
has '"INCOMPLETE"'
EXPLAIN_CODE="$(curl -s -o /dev/null -w "%{http_code}" -H "X-CS-Token: $TOKEN" "$URL/api/explain?q=vpn")"
if [[ "$EXPLAIN_CODE" == "200" ]]; then
  ok api GET "/api/explain?q=vpn"
  has "vpn"
else
  skip "the console's Explain panel API (/api/explain) is not in this build"
fi
ok cs explain
ok cs explain ui
has "127.0.0.1|token"
ok cs explain feature finops
has "OpenCost|opencost"

step "4. One audit trail for every entry point"
ok tail -n 2 "$CLOUDSEED_HOME/envs/aws-web/logs/audit.jsonl"
check "the wizard's job is recorded via the ui" grep -q '"via": "ui"' "$CLOUDSEED_HOME/envs/aws-web/logs/audit.jsonl"
ok cs ui logs -n 20
has "job .* cloudseed setup aws"

step "5. FinOps: know the cost before you apply"
ok cs finops estimate aws --env web
has "total / month +\\\$[0-9]+\.[0-9]{2}"
ok job cloudseed_finops '{"action": "estimate", "cloud": "aws", "env": "web"}'
has "total / month"
ok cs finops report aws --env web --save
has "Report saved"
check "finops/latest.json written" test -f "$CLOUDSEED_HOME/envs/aws-web/finops/latest.json"
rc 1 cs finops cloud aws --env web --days 7
has "Cloud bill unavailable"

step "6. Kubernetes cost allocation with OpenCost"
skip "cs platform install finops / cs finops k8s (a cluster)"
skip "cs agentic \"look at my finops report ...\" (a model)"
rc 1 cs finops k8s aws --env web --by namespace --window 24h
has "No Kubernetes cluster in aws-web"

step "7. Manage the console"
ok cs ui restart
has "UI restarted"
ok cs ui stop
has "UI stopped"
ok cs ui start --no-open
has "cloudseed console is up"
OLD="$TOKEN"
ok cs ui token --rotate
has "New token issued"
check "the old link stops working" test "$(curl -s -o /dev/null -w '%{http_code}' -H "X-CS-Token: $OLD" "$URL/api/state")" = "401"
ok cs ui stop
cs ui serve --port "$PORT2" </dev/null >"$SCN_TMP/serve.log" 2>&1 &
SERVE_PID=$!
on_exit kill "$SERVE_PID"
check "cs ui serve answers in the foreground" bash -c "for i in \$(seq 1 30); do curl -s http://127.0.0.1:$PORT2/health | grep -q cloudseed-ui && exit 0; sleep 1; done; exit 1"
kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
ok cs ui start --no-open --port "$PORT"

step "Verify it worked"
ok cs ui status
has "Enabled +yes"
ok ls "$CLOUDSEED_HOME/envs/aws-web/finops/"
has "latest.json"

step "Clean up"
ok cs disable ui
has "UI disabled"
ok cs destroy aws -y --env web --purge --auto-approve
check "nothing listens on the console port" bash -c "! curl -s -m 2 $URL/health >/dev/null"
