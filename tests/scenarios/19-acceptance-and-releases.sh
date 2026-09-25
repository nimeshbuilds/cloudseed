#!/usr/bin/env bash
# Scenario 19 - Guarded acceptance and trusted releases (docs/scenarios/19-acceptance-and-releases.md)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 19-acceptance-and-releases "Guarded acceptance and trusted releases" local
need python3
step "1. Preview each provider's lifecycle with missing guards explicitly reported"
for cloud in aws gcp azure; do
  rc 3 cs ops acceptance "$cloud" --json
  has '"live": false'
  has '"verdict": "INCOMPLETE"'
done
rc 2 cs ops acceptance aws --live --json
has 'approve|approval'
step "2. Inspect storage and preview keychain migration"
ok cs ops credentials-backend --json
has '"backend": "file"'
ok cs ops credentials-backend --params '{"backend":"os-keychain"}' --json
has '"changed": false'
step "3. Verify bytes without pretending a self-generated checksum authenticates a release"
printf 'fixture artifact\n' > artifact.txt
PARAMS="$(python3 -c 'import hashlib,json; print(json.dumps({"artifact":"artifact.txt","sha256":hashlib.sha256(open("artifact.txt","rb").read()).hexdigest()}))')"
rc 3 cs ops release-verify --params "$PARAMS" --json
has '"integrity": true'
has '"provenance_verified": false'
PARAMS="$(python3 -c 'import json; print(json.dumps({"artifact":"artifact.txt","sha256":"0"*64}))')"
rc 1 cs ops release-verify --params "$PARAMS" --json
has '"verdict": "FAIL"'
skip "Cloud create/restore/destroy needs sandbox identity, region and spending authorization. Native keychain migration and signed release verification require their real services; this scenario does not modify the operator keychain."
