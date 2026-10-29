#!/usr/bin/env bash
# CI only: restore the old total timeout and prove the real 32s test detects it.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || exit 2
original=$(mktemp)
cp rescue/host_authorization.go "$original"
trap 'cp "$original" rescue/host_authorization.go; rm -f "$original"' EXIT
python3 - <<'PY'
from pathlib import Path
path = Path('rescue/host_authorization.go')
text = path.read_text()
old = '&http.Client{Transport: authorizationWatchTransport}'
assert text.count(old) == 1, 'Production watch constructor changed; review negative control'
path.write_text(text.replace(old, '&http.Client{Transport: authorizationWatchTransport, Timeout: 30 * time.Second}'))
PY
set +e
bash scripts/ci/run-go-tests.sh -race -run '^TestRescueAuthorizationWatchSurvivesThirtySeconds$' ./rescue
status=$?
set -e
python3 - "$KOMARI_TEST_LOG_DIR" "$status" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
events = [json.loads(line) for line in (root / 'tests.jsonl').read_text().splitlines()]
name = 'TestRescueAuthorizationWatchSurvivesThirtySeconds'
failed = [e for e in events if e.get('Test') == name and e.get('Action') == 'fail']
output = ''.join(e.get('Output', '') for e in events if e.get('Test') == name)
assert int(sys.argv[2]) != 0 and failed, 'Old timeout did not fail the actual runtime test (a build failure is insufficient)'
assert 'stream ended at' in output and 'Client.Timeout' in output, output
print('Negative control detected the original HTTP total-timeout failure; complete failing logs retained.')
PY
