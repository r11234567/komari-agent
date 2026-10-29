#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'CI only';exit 2; }
backup=$(mktemp)
cp rescue/host_authorization.go "$backup"
trap 'cp "$backup" rescue/host_authorization.go;rm -f "$backup"' EXIT
python3 - <<'PY'
from pathlib import Path
p=Path('rescue/host_authorization.go');s=p.read_text()
needle='changes, watchErr := credentials.WatchChanges(ctx, h.manifest.CredentialsFile)'
assert s.count(needle)==1
p.write_text(s.replace(needle,needle+'\n changes = nil // deliberate CI regression'))
PY
bash scripts/ci/run-audit-check.sh credential-broken-handoff-build go test -race -c -o /tmp/credential-broken-rescue.test ./rescue
set +e
bash scripts/ci/run-audit-check.sh credential-broken-handoff sudo env KOMARI_CREDENTIAL_ROOT_TEST=1 /tmp/credential-broken-rescue.test -test.v -test.run '^TestCredentialHandoff'
status=$?
set -e
[[ "$status" -ne 0 ]] || { echo 'Disabled notifications unexpectedly passed';exit 1; }
python3 - <<'PY'
from pathlib import Path
log=Path('ci-artifacts/credential-broken-handoff.log').read_text()
assert '--- FAIL: TestCredentialHandoffPreservesFreshLeaseAndHonorsRevocation' in log
assert 'credential notification did not reconnect within freshness window' in log
print('Observed intended runtime handoff failure; full log retained.')
PY
