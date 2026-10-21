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
if sudo "$rootdir/komari-host" apply --manifest "/etc/komari/services/$service.json"; then echo 'Unimplemented apply must fail' >&2; exit 1; fi
legacy="komari-migrate-${GITHUB_RUN_ID}"
legacydir="/var/lib/$legacy"
sudo install -d -m 755 "$legacydir"
for file in credentials runtime-config privileged nonces; do
  printf '{"fixture":"preserve-node-id-and-r4","revision":4}\n' | sudo tee "$legacydir/$file.json" >/dev/null
done
sudo cp "$rootdir/komari-agent" "$legacydir/agent"
sudo chown -R komari-ci-test "$legacydir"
sudo sha256sum "$legacydir/"*.json > ci-artifacts/migration-state-before.sha256
sudo tee "/etc/systemd/system/$legacy.service" >/dev/null <<UNIT
[Service]
User=komari-ci-test
ExecStart=$legacydir/agent --endpoint https://panel.invalid --credentials-file $legacydir/credentials.json --runtime-state-file $legacydir/runtime-config.json --privileged-state-file $legacydir/privileged.json --replay-state-file $legacydir/nonces.json --disable-remote-control
UNIT
sudo systemctl daemon-reload
sudo "$rootdir/komari-host" migrate --service "$legacy" --legacy-disable preserve
sum=$(sha256sum "$rootdir/komari-agent");sum=${sum%% *}
sudo "$rootdir/komari-host" migrate --service "$legacy" --legacy-disable preserve --agent-artifact "$rootdir/komari-agent" --sha256 "$sum" --commit
if sudo "$rootdir/komari-agent" --service-manifest "/etc/komari/services/$legacy.json" upgrade; then
  echo 'Root CLI must not declare a non-root daemon upgraded' >&2; exit 1
fi
sudo sha256sum -c ci-artifacts/migration-state-before.sha256
sudo -u komari-ci-test test ! -w "/usr/lib/komari/$legacy/komari-host"
sudo test -f "/var/lib/komari-host/$legacy/unit-0.backup"
echo 'Trusted fresh install, custom legacy migration, preserved node/revision files, and unsupported host apply verified.'
