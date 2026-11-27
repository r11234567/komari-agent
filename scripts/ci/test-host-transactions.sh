#!/usr/bin/env bash
# Mutates only disposable GitHub runners. Never run this on production.
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ]; then echo 'Disposable GitHub runner required' >&2; exit 1; fi
mkdir -p ci-artifacts
exec > >(tee ci-artifacts/host-transactions.log) 2>&1
service="komari-stage6-${GITHUB_RUN_ID}"
rootdir="/usr/lib/komari/$service"
ssh_launcher="$rootdir/host-acceptance-run"
ssh_fixture=
ssh_namespace="komari-approval-ci"
sudo_rule=/etc/sudoers.d/komari-approval-fixture
collect() {
  status=$?
  if [[ -n "$ssh_fixture" ]]; then
    if sudo test -f "$ssh_fixture/sshd.pid"; then
      sudo kill "$(sudo cat "$ssh_fixture/sshd.pid")" 2>/dev/null || true
    fi
    sudo ip netns del "$ssh_namespace" 2>/dev/null || true
    sudo ip link del komari-ci-host 2>/dev/null || true
    sudo rm -f "$sudo_rule"
    sudo rm -rf -- "$ssh_fixture"
  fi
  echo "$status" > ci-artifacts/host-transactions-exit.txt
  sudo systemctl show "$service" "$service-rescue" --property=User,Group,MainPID,NoNewPrivileges,CapabilityBoundingSet,ActiveState,SubState > ci-artifacts/host-services.log 2>&1 || true
  sudo journalctl -u "$service" -u "$service-rescue" --no-pager -o short-precise > ci-artifacts/host-journald.log 2>&1 || true
  sudo journalctl -k --no-pager -n 150 > ci-artifacts/host-kernel.log 2>&1 || true
  sudo stat -c '%n uid=%u gid=%g mode=%a' /run/komari "/run/komari/$service.helper.json" > ci-artifacts/host-heartbeat-paths.log 2>&1 || true
  # This heartbeat is public process evidence, never enrollment credentials.
  sudo cat "/run/komari/$service.helper.json" > ci-artifacts/host-heartbeat.json 2>&1 || true
  # Root journals contain state backups/credentials. Export only phase and
  # ownership metadata, never raw backup or bootstrap contents.
  sudo python3 - "$service" <<'PY' > ci-artifacts/host-journals.json
import glob,json,sys
rows=[]
for path in glob.glob('/var/lib/komari-host/'+sys.argv[1]+'*/transaction.json'):
 try:
  j=json.load(open(path)); row={k:j.get(k) for k in ['version','operation_id','phase','fence_stage','operator','error','previous_mode','previous_uid','previous_helper','legacy_remote_control_consent','ownership','recovery_ownership']}; row['pending_receipt']=bool(j.get('receipt')); row['superseded_receipt_count']=len(j.get('superseded_receipts',[])); rows.append(row)
 except Exception as e: rows.append({'path':path,'error':str(e)})
print(json.dumps(rows,indent=2))
PY
  sudo python3 - "$service" <<'PY' > ci-artifacts/software-upgrade-journals.json
import glob,json,sys
rows=[]
# Only upgrade metadata; never the numbered program/configuration backups.
for path in glob.glob('/var/lib/komari-host/'+sys.argv[1]+'/upgrade-*/*.json'):
 try:
  j=json.load(open(path))
  rows.append(dict(path=path, **{k:j.get(k) for k in ['phase','version','manifest','paths','modes','active','at','previous_attempt']}))
 except Exception as e: rows.append({'path':path,'error':str(e)})
print(json.dumps(rows,indent=2))
PY
  exit "$status"
}
trap collect EXIT
sudo apt-get update -qq
sudo apt-get install -y iproute2 openssh-client openssh-server pamtester
sudo useradd --system --no-create-home --shell /usr/sbin/nologin komari-stage6-agent
sudo useradd --create-home --shell /bin/bash komari-stage6-admin
sudo install -d -m 755 "$rootdir"
export GOMAXPROCS=2
go build -p=2 -ldflags="-X github.com/komari-monitor/komari-agent/internal/hostcmd.ReleaseVersion=ci-stage6" -o ci-artifacts/komari-host ./cmd/komari-host
go build -p=2 -o ci-artifacts/komari-agent .
go build -p=2 -o ci-artifacts/komari-agent-rescue ./cmd/komari-agent-rescue
sudo install -m 755 ci-artifacts/komari-host "$rootdir/komari-host"
sudo install -m 755 ci-artifacts/komari-agent "$rootdir/komari-agent"
sudo install -m 755 ci-artifacts/komari-agent-rescue "$rootdir/helper-release"
go test -p=2 -c -o ci-artifacts/host-acceptance.test ./internal/hostcmd

# Run the same transaction suite under an actual OpenSSH/PAM session from a
# separate network namespace. Only the fixture launcher is granted sudo.
ssh_fixture=$(sudo mktemp -d /run/komari-approval-ci.XXXXXXXX)
sudo chmod 0755 "$ssh_fixture"
sudo install -m 0755 ci-artifacts/host-acceptance.test "$rootdir/host-acceptance.test"
sudo ssh-keygen -q -t ed25519 -N '' -f "$ssh_fixture/server"
sudo ssh-keygen -q -t ed25519 -N '' -f "$ssh_fixture/client"
sudo install -m 0644 "$ssh_fixture/client.pub" "$ssh_fixture/authorized_keys"
{
  printf '#!/usr/bin/env bash\n'
  printf 'cd %q\n' "$PWD"
  printf 'export GITHUB_ACTIONS=true KOMARI_STAGE6_ACCEPTANCE=true KOMARI_STAGE6_SERVICE=%q\n' "$service"
  printf 'exec %q -test.v -test.run %q -test.timeout=10m\n' "$rootdir/host-acceptance.test" '^TestHost(StateFence|RescuePrepare|SystemdTransactionAcceptance)'
} | sudo tee "$ssh_launcher" >/dev/null
sudo chmod 0755 "$ssh_launcher"
printf 'komari-stage6-admin ALL=(root) NOPASSWD: %s\n' "$ssh_launcher" | sudo tee "$ssh_fixture/sudoers" >/dev/null
sudo visudo -cf "$ssh_fixture/sudoers"
sudo install -m 0440 "$ssh_fixture/sudoers" "$sudo_rule"
printf 'komari-stage6-admin:%s\n' "$(openssl rand -hex 24)" | sudo chpasswd

sudo ip netns add "$ssh_namespace"
sudo ip link add komari-ci-host type veth peer name komari-ci-peer netns "$ssh_namespace"
sudo ip addr add 192.0.2.1/30 dev komari-ci-host
sudo ip link set komari-ci-host up
sudo ip -n "$ssh_namespace" addr add 192.0.2.2/30 dev komari-ci-peer
sudo ip -n "$ssh_namespace" link set komari-ci-peer up
sudo ip -n "$ssh_namespace" link set lo up
sudo install -d -m 0755 /run/sshd
sudo tee "$ssh_fixture/sshd_config" >/dev/null <<EOF
Port 22327
ListenAddress 192.0.2.1
HostKey $ssh_fixture/server
PidFile $ssh_fixture/sshd.pid
AuthorizedKeysFile $ssh_fixture/authorized_keys
UsePAM yes
UseDNS no
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers komari-stage6-admin
DisableForwarding yes
ForceCommand /usr/bin/sudo -n $ssh_launcher
EOF
{ printf '[192.0.2.1]:22327 '; sudo cat "$ssh_fixture/server.pub"; } | sudo tee "$ssh_fixture/known_hosts" >/dev/null
sudo /usr/sbin/sshd -f "$ssh_fixture/sshd_config"
sudo ip netns exec "$ssh_namespace" ssh -tt -p 22327 -i "$ssh_fixture/client" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=$ssh_fixture/known_hosts" komari-stage6-admin@192.0.2.1 \
  | tee ci-artifacts/host-transactions-tests.log
