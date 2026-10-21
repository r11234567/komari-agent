#!/usr/bin/env bash
# Only for disposable GitHub Linux runners; never run on a production node.
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ]; then echo 'Disposable GitHub runner required' >&2; exit 1; fi
mkdir -p ci-artifacts
exec > >(tee ci-artifacts/trusted-install.log) 2>&1
trap 'status=$?; echo "$status" > ci-artifacts/trusted-install-exit.txt; exit "$status"' EXIT
service="komari-stage3-${GITHUB_RUN_ID}"
rootdir="/usr/lib/komari/$service"
sudo install -d -m 755 "$rootdir"
go build -p=2 -o ci-artifacts/komari-host ./cmd/komari-host
go build -p=2 -o ci-artifacts/komari-agent .
sudo install -m 755 ci-artifacts/komari-host "$rootdir/komari-host"
sudo install -m 755 ci-artifacts/komari-agent "$rootdir/komari-agent"
sudo useradd --system --no-create-home --shell /usr/sbin/nologin komari-ci-test
sudo "$rootdir/komari-host" install --service "$service" --user komari-ci-test --binary-dir "$rootdir" -- --endpoint https://panel.invalid --disable-remote-control
sudo -u komari-ci-test test ! -w "$rootdir/komari-host"
sudo -u komari-ci-test test ! -w "$rootdir/komari-agent"
sudo -u komari-ci-test test ! -w "/etc/komari/services/$service.policy.json"
sudo -u komari-ci-test test -w "/var/lib/komari/$service"
sudo "$rootdir/komari-host" diagnose --manifest "/etc/komari/services/$service.json"
if sudo "$rootdir/komari-host" apply --manifest "/etc/komari/services/$service.json"; then echo 'Apply without a revision and approved trust must fail' >&2; exit 1; fi
legacy="komari-migrate-${GITHUB_RUN_ID}"
legacydir="/var/lib/$legacy"
sudo install -d -m 755 "$legacydir"
printf '{"fixture":"preserve-node-id"}\n' | sudo tee "$legacydir/credentials.json" >/dev/null
printf '{"current":{"revision":4,"report_interval":3000000000}}\n' | sudo tee "$legacydir/runtime-config.json" >/dev/null
printf '{"applied_revision":0}\n' | sudo tee "$legacydir/privileged.json" >/dev/null
printf '{}\n' | sudo tee "$legacydir/nonces.json" >/dev/null
sudo cp "$rootdir/komari-agent" "$legacydir/agent"
sudo chown -R komari-ci-test "$legacydir"
sudo sha256sum "$legacydir/"*.json > ci-artifacts/migration-state-before.sha256
sudo tee "/etc/systemd/system/$legacy.service" >/dev/null <<UNIT
[Service]
User=komari-ci-test
ExecStart=$legacydir/agent --endpoint https://panel.invalid --credentials-file $legacydir/credentials.json --runtime-state-file $legacydir/runtime-config.json --privileged-state-file $legacydir/privileged.json --replay-state-file $legacydir/nonces.json --disable-remote-control --interval 12 --include-nics eth0 --detailed-gpu
UNIT
sudo systemctl daemon-reload
sudo "$rootdir/komari-host" migrate --service "$legacy" --legacy-disable preserve
sum=$(sha256sum "$rootdir/komari-agent");sum=${sum%% *}
sudo "$rootdir/komari-host" migrate --service "$legacy" --legacy-disable preserve --agent-artifact "$rootdir/komari-agent" --sha256 "$sum" --commit
if sudo "$rootdir/komari-agent" --service-manifest "/etc/komari/services/$legacy.json" upgrade; then
  echo 'Root CLI must not declare a non-root daemon upgraded' >&2; exit 1
fi
sudo -u komari-ci-test "/usr/lib/komari/$legacy/komari-agent" config show --json > ci-artifacts/migration-config.json
sudo -u komari-ci-test "/usr/lib/komari/$legacy/komari-agent" recover version
sudo systemctl show "$legacy" --property=ExecStart > ci-artifacts/migration-execstart.log
python3 - <<'CHECK'
import json
from pathlib import Path
p=json.loads(Path('ci-artifacts/migration-config.json').read_text())
assert p['runtime']['revision']==4, 'migration lost applied runtime revision'
unit=Path('ci-artifacts/migration-execstart.log').read_text()
assert '--interval' not in unit and '--detailed-gpu' not in unit and '--include-nics' not in unit
assert '--config' in unit and '.migration-bootstrap.json' in unit
CHECK
sudo sha256sum -c ci-artifacts/migration-state-before.sha256
sudo -u komari-ci-test test ! -w "/usr/lib/komari/$legacy/komari-host"
sudo test -f "/var/lib/komari-host/$legacy/unit-0.backup"
echo 'Trusted install, retired-argv migration, service-account config query, preserved node/revision files, and invalid host apply verified.'
