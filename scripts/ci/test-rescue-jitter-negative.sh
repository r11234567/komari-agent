#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'CI only'; exit 2; }
backup=$(mktemp)
cp rescue/host_authorization.go "$backup"
trap 'cp "$backup" rescue/host_authorization.go; rm -f "$backup"' EXIT
python3 - <<'PY'
from pathlib import Path
p=Path('rescue/host_authorization.go')
s=p.read_text()
needle='const authorizationSilence = 10 * time.Second'
assert s.count(needle)==1
p.write_text(s.replace(needle,'const authorizationSilence = 2 * time.Second'))
PY
bash scripts/ci/run-audit-check.sh credential-broken-jitter-build go test -race -c -o /tmp/credential-broken-jitter.test ./rescue
set +e
bash scripts/ci/run-audit-check.sh credential-broken-jitter sudo env KOMARI_CREDENTIAL_ROOT_TEST=1 /tmp/credential-broken-jitter.test -test.v -test.run '^TestRescueAuthorizationJitterAndBoundedSilence$'
status=$?
set -e
[[ "$status" -ne 0 ]] || { echo 'Old two-second jitter bound unexpectedly passed';exit 1; }
python3 - <<'PY'
from pathlib import Path
log=Path('ci-artifacts/credential-broken-jitter.log').read_text()
assert '--- FAIL: TestRescueAuthorizationJitterAndBoundedSilence' in log
assert 'three-second heartbeat gap revoked a healthy stream' in log
assert '--- SKIP:' not in log
print('Old two-second bound failed the real signed-stream jitter assertion; full logs retained.')
PY
