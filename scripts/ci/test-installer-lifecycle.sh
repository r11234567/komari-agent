#!/usr/bin/env bash
# Disposable runner only. Exercise the real downloaded-script entry point and
# real host tool/systemd. The small daemon fixture isolates installer lifecycle
# from enrollment; the separate host-transaction suite runs the real daemon.
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ]; then echo 'Disposable GitHub runner required' >&2; exit 1; fi
root=$(pwd)
log_dir="$root/ci-artifacts/installer-lifecycle"
mkdir -p "$log_dir"
exec > >(tee "$log_dir/lifecycle.log") 2>&1
service="komari-installer-${GITHUB_RUN_ID}"
legacy="komari-installer-legacy-${GITHUB_RUN_ID}"
fixture="/usr/lib/komari/installer-fixture-${GITHUB_RUN_ID}"
saved_parent="/var/lib/komari-installer-parent-${GITHUB_RUN_ID}"
cleanup() {
    local status=$?
    trap - EXIT
    if sudo test -L /var/lib/komari && sudo test -d "$saved_parent"; then
        sudo unlink /var/lib/komari
        sudo mv "$saved_parent" /var/lib/komari
    fi
    for unit in "$service" "$legacy"; do
        sudo systemctl show "$unit" --property=ActiveState,SubState,MainPID,Result > "$log_dir/$unit-status.log" 2>&1 || true
        sudo journalctl -u "$unit" --no-pager > "$log_dir/$unit-journal.log" 2>&1 || true
        sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    sudo namei -l /var/lib/komari > "$log_dir/state-parent.log" 2>&1 || true
    printf '%s\n' "$status" > "$log_dir/exit-code.txt"
    exit "$status"
}
trap cleanup EXIT
sudo install -d -m 755 "$fixture" "$fixture/mock-bin" /var/lib/komari
cat > "$log_dir/daemon.go" <<'DAEMON'
package main
import("fmt";"os";"os/signal";"syscall")
var version string
func main(){if version=="bad"{fmt.Println("intentional installer regression failure");os.Exit(42)};fmt.Println("installer fixture",version);c:=make(chan os.Signal,1);signal.Notify(c,syscall.SIGTERM,syscall.SIGINT);<-c}
DAEMON
for version in v1 v2 bad; do
    go build -p=2 -ldflags="-X main.version=$version" -o "$log_dir/agent-$version" "$log_dir/daemon.go"
    sudo install -m 755 "$log_dir/agent-$version" "$fixture/agent-$version"
done
sudo install -m 755 ci-artifacts/komari-host "$fixture/komari-host"
cat > "$log_dir/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
output=""
while [ "$#" -gt 0 ]; do
    case "$1" in -o) output="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
done
case "${url##*/}" in
    komari-agent-linux-*) source="$KOMARI_INSTALLER_FIXTURE_AGENT" ;;
    komari-host-linux-*) source="$KOMARI_INSTALLER_FIXTURE_HOST" ;;
    *) echo "Unexpected fixture request" >&2; exit 1 ;;
esac
if [[ "$url" = *.sha256 ]]; then
    if [ "${KOMARI_INSTALLER_FIXTURE_BAD_HASH:-}" = 1 ]; then printf '%064d  fixture\n' 0; else sha256sum "$source"; fi
else
    [ -n "$output" ]
    cp "$source" "$output"
fi
CURL
sudo install -m 755 "$log_dir/curl" "$fixture/mock-bin/curl"
run_installer() {
    local unit="$1" agent="$2"; shift 2
    sudo env PATH="$fixture/mock-bin:$PATH" \
        KOMARI_INSTALLER_FIXTURE_AGENT="$fixture/agent-$agent" \
        KOMARI_INSTALLER_FIXTURE_HOST="$fixture/komari-host" \
        KOMARI_INSTALLER_FIXTURE_BAD_HASH="${fixture_bad_hash:-}" \
        bash "$root/install.sh" --install-service-name "$unit" \
        --install-dir "/usr/lib/komari/$unit" --install-version "fixture-$agent" "$@"
}

# Reproduce the reported failure: an old installer made the shared state parent
# the service account's mode-0700 home and left two binaries after a failed try.
if ! id -u komari >/dev/null 2>&1; then
    sudo useradd --system --no-create-home --home-dir /var/lib/komari --shell /usr/sbin/nologin komari
fi
test "$(getent passwd komari | cut -d: -f6)" = /var/lib/komari
sudo chown "$(id -u komari):$(id -g komari)" /var/lib/komari
sudo chmod 700 /var/lib/komari
sudo -u komari touch /var/lib/komari/legacy-home-sentinel
sudo install -d -m 755 "/usr/lib/komari/$service"
sudo install -m 755 "$fixture/agent-v1" "/usr/lib/komari/$service/komari-agent"
sudo install -m 755 "$fixture/komari-host" "/usr/lib/komari/$service/komari-host"
run_installer "$service" v1 --endpoint https://panel.invalid
test "$(sudo stat -c '%u:%g:%a' /var/lib/komari)" = 0:0:755
test "$(sudo stat -c '%u' /var/lib/komari/legacy-home-sentinel)" = "$(id -u komari)"
sudo -u komari test -w "/var/lib/komari/$service"
sudo -u komari test ! -w "/usr/lib/komari/$service/komari-host"
for name in credentials runtime-config privileged nonces; do
    printf '{"installer_fixture":"%s","node_identity":"unchanged"}\n' "$name" | sudo -u komari tee "/var/lib/komari/$service/$name.json" >/dev/null
done
sudo sha256sum "/var/lib/komari/$service/"*.json "/etc/komari/services/$service"*.json "/etc/systemd/system/$service.service" > "$log_dir/update-state-before.sha256"
sudo systemctl start "$service"
old_pid=$(sudo systemctl show "$service" --property=MainPID --value)

# A bad download must not replace either installed binary or restart the daemon.
fixture_bad_hash=1
if run_installer "$service" v2; then echo 'Bad checksum was accepted' >&2; exit 1; fi
unset fixture_bad_hash
sudo cmp "$fixture/agent-v1" "/usr/lib/komari/$service/komari-agent"
test "$(sudo systemctl show "$service" --property=MainPID --value)" = "$old_pid"

# The same public entry point updates an existing active service while keeping
# every identity/configuration/policy file and the unit byte-for-byte unchanged.
run_installer "$service" v2
sudo cmp "$fixture/agent-v2" "/usr/lib/komari/$service/komari-agent"
sudo sha256sum -c "$log_dir/update-state-before.sha256"
test "$(sudo systemctl show "$service" --property=MainPID --value)" != "$old_pid"
sudo systemctl is-active --quiet "$service"

# A daemon that fails after replacement must report failure and recover the
# previous working binaries rather than claim that installation succeeded.
if run_installer "$service" bad; then echo 'Failed daemon update reported success' >&2; exit 1; fi
sleep 1
sudo cmp "$fixture/agent-v2" "/usr/lib/komari/$service/komari-agent"
sudo systemctl is-active --quiet "$service"
sudo sha256sum -c "$log_dir/update-state-before.sha256"

# Reproduce a live legacy /opt-style service. Migration must retain the original
# account, explicit state paths, identity bytes and local deny, including retired
# argv, while replacing only the executable/service bootstrap through hostcmd.
legacydir="/var/lib/$legacy"
sudo install -d -m 755 "$legacydir"
sudo install -m 755 "$fixture/agent-v1" "$legacydir/agent"
for name in credentials runtime-config privileged nonces; do
    printf '{}\n' | sudo tee "$legacydir/$name.json" >/dev/null
done
sudo chown -R "$(id -u komari):$(id -g komari)" "$legacydir"
sudo sha256sum "$legacydir/"*.json > "$log_dir/legacy-state-before.sha256"
sudo tee "/etc/systemd/system/$legacy.service" >/dev/null <<UNIT
[Service]
User=komari
WorkingDirectory=$legacydir
ExecStart=$legacydir/agent --endpoint https://panel.invalid --credentials-file $legacydir/credentials.json --runtime-state-file $legacydir/runtime-config.json --privileged-state-file $legacydir/privileged.json --replay-state-file $legacydir/nonces.json --disable-remote-control --interval 12
UNIT
sudo systemctl daemon-reload
sudo systemctl start "$legacy"
run_installer "$legacy" v2
sudo systemctl is-active --quiet "$legacy"
sudo sha256sum -c "$log_dir/legacy-state-before.sha256"
sudo python3 - "$legacy" <<'CHECK'
import json, sys
from pathlib import Path
service = sys.argv[1]
m = json.loads(Path('/etc/komari/services/'+service+'.json').read_text())
p = json.loads(Path('/etc/komari/services/'+service+'.policy.json').read_text())
assert m['service_user'] == 'komari'
assert m['credentials_file'] == '/var/lib/'+service+'/credentials.json'
assert p['force_deny_remote_control'] is True
CHECK

# Symlinks and unknown owners must still fail instead of weakening trust checks.
sudo systemctl stop "$service" "$legacy"
sudo mv /var/lib/komari "$saved_parent"
sudo ln -s "$saved_parent" /var/lib/komari
if run_installer "${service}-symlink" v1; then echo 'Symlink state parent accepted' >&2; exit 1; fi
sudo unlink /var/lib/komari
sudo mv "$saved_parent" /var/lib/komari
sudo chown nobody /var/lib/komari
if run_installer "${service}-owner" v1; then echo 'Unknown state owner accepted' >&2; exit 1; fi
test "$(sudo stat -c '%u' /var/lib/komari)" = "$(id -u nobody)"
sudo chown root:root /var/lib/komari
sudo chmod 755 /var/lib/komari
echo 'Installer home collision, failed-attempt retry, verified active update, rollback, legacy migration and trust boundaries passed.'
