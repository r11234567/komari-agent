#!/usr/bin/env bash
# Mutates only disposable GitHub runners. Never run this on production.
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ]; then echo 'Disposable GitHub runner required' >&2; exit 1; fi
mkdir -p ci-artifacts
exec > >(tee ci-artifacts/host-transactions.log) 2>&1
service="komari-stage6-${GITHUB_RUN_ID}"
rootdir="/usr/lib/komari/$service"
collect() {
  status=$?
  echo "$status" > ci-artifacts/host-transactions-exit.txt
  sudo systemctl show "$service" "$service-rescue" --property=User,Group,MainPID,NoNewPrivileges,CapabilityBoundingSet,ActiveState,SubState > ci-artifacts/host-services.log 2>&1 || true
  sudo journalctl -u "$service" -u "$service-rescue" --no-pager -o short-precise > ci-artifacts/host-journald.log 2>&1 || true
  sudo journalctl -k --no-pager -n 150 > ci-artifacts/host-kernel.log 2>&1 || true
  # Root journals contain state backups/credentials. Export only phase and
  # ownership metadata, never raw backup or bootstrap contents.
  sudo python3 - "$service" <<'PY' > ci-artifacts/host-journals.json
import glob,json,sys
rows=[]
for path in glob.glob('/var/lib/komari-host/'+sys.argv[1]+'*/transaction.json'):
 try:
  j=json.load(open(path)); rows.append({k:j.get(k) for k in ['version','operation_id','phase','operator','error','previous_mode','previous_helper','ownership']})
 except Exception as e: rows.append({'path':path,'error':str(e)})
print(json.dumps(rows,indent=2))
PY
  exit "$status"
}
trap collect EXIT
sudo apt-get update -qq
sudo apt-get install -y pamtester
sudo useradd --system --no-create-home --shell /usr/sbin/nologin komari-stage6-agent
sudo useradd --no-create-home --shell /bin/bash komari-stage6-admin
sudo install -d -m 755 "$rootdir"
export GOMAXPROCS=2
go build -p=2 -o ci-artifacts/komari-host ./cmd/komari-host
go build -p=2 -o ci-artifacts/komari-agent .
go build -p=2 -o ci-artifacts/komari-agent-rescue ./cmd/komari-agent-rescue
sudo install -m 755 ci-artifacts/komari-host "$rootdir/komari-host"
sudo install -m 755 ci-artifacts/komari-agent "$rootdir/komari-agent"
sudo install -m 755 ci-artifacts/komari-agent-rescue "$rootdir/helper-release"
go test -p=2 -c -o ci-artifacts/host-acceptance.test ./internal/hostcmd
sudo env GITHUB_ACTIONS=true KOMARI_STAGE6_ACCEPTANCE=true KOMARI_STAGE6_SERVICE="$service" ci-artifacts/host-acceptance.test -test.v -test.run '^TestHostSystemdTransactionAcceptance$' -test.timeout=10m | tee ci-artifacts/host-transactions-tests.log
