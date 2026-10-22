#!/usr/bin/env bash
# Disposable GitHub runner only: test install.sh with the real host tool.
# The downloads are local fixtures; no enrollment or production service is used.
set -Eeuo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ]; then echo 'Disposable GitHub runner required' >&2; exit 1; fi
root=$(pwd)
log_dir="$root/ci-artifacts/installer-recovery"
mkdir -p "$log_dir"
: > "$log_dir/release-requests.log"
exec > >(tee "$log_dir/recovery.log") 2>&1
service="komari-installer-${GITHUB_RUN_ID}"
pristine="$service-pristine"
legacy="$service-legacy"
legacy_dir="/var/lib/$legacy"
fixture="/usr/lib/komari/installer-fixture-${GITHUB_RUN_ID}"
saved_parent="/var/lib/komari-installer-parent-${GITHUB_RUN_ID}"
cleanup() {
    local status=$?
    trap - EXIT
    set +e
    mkdir -p "$log_dir/installer-logs"
    if sudo test -d /var/lib/komari-host/installer-logs; then
        sudo cp -a /var/lib/komari-host/installer-logs/. "$log_dir/installer-logs/" || true
        sudo chown -R "$(id -u):$(id -g)" "$log_dir/installer-logs" || true
    fi
    if sudo test -L /var/lib/komari && sudo test -d "$saved_parent"; then
        sudo unlink /var/lib/komari
        sudo mv "$saved_parent" /var/lib/komari
    fi
    for unit in "$service" "$pristine" "$legacy"; do
        sudo systemctl show "$unit" --property=ActiveState,SubState,Result > "$log_dir/$unit-status.log" 2>&1 || true
        sudo journalctl -u "$unit" --no-pager > "$log_dir/$unit-journal.log" 2>&1 || true
        sudo namei -l "/usr/lib/komari/$unit/komari-agent" > "$log_dir/$unit-executable-permissions.log" 2>&1 || true
        sudo namei -l "/etc/komari/services/$unit.json" > "$log_dir/$unit-registry-permissions.log" 2>&1 || true
        sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    sudo namei -l /var/lib/komari > "$log_dir/state-parent.log" 2>&1 || true
    getent passwd komari > "$log_dir/service-account.log" || true
    printf '%s\n' "$status" > "$log_dir/exit-code.txt"
    # The installer uses umask 077 and sudo creates some fixture logs as root.
    # The upload action runs as runner and must read every retained file.
    sudo chown -R "$(id -u):$(id -g)" "$log_dir" || true
    exit "$status"
}
trap cleanup EXIT
trap 'printf "FAILED at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

# GitHub images may make this directory runner-owned. Prepare the root-owned
# command directory required by the existing installer, only on this runner.
sudo stat -c '%u:%g:%a %n' /usr/local/bin > "$log_dir/runner-command-dir-before.log"
sudo chown root:root /usr/local/bin
sudo chmod go-w /usr/local/bin
sudo install -d -m 755 "$fixture" "$fixture/mock-bin"
sudo install -m 755 ci-artifacts/komari-agent "$fixture/komari-agent"
sudo install -m 755 ci-artifacts/komari-host "$fixture/komari-host"
cat > "$log_dir/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
output=""
while [ "$#" -gt 0 ]; do
    case "$1" in -o) output="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
done
case "${url##*/}" in
    komari-agent-linux-*) component=komari-agent ;;
    komari-host-linux-*) component=komari-host ;;
    *) echo 'Unexpected fixture request' >&2; exit 1 ;;
esac
source="$KOMARI_INSTALLER_FIXTURE/$component"
if [ "$component" = komari-agent ] && [ "${KOMARI_INSTALLER_BAD_BINARY:-}" = true ]; then
    source="$KOMARI_INSTALLER_FIXTURE/komari-agent-bad"
fi
if [ "$component" = komari-agent ] && [ "${KOMARI_INSTALLER_LIVE_BINARY:-}" = true ]; then
    source="$KOMARI_INSTALLER_FIXTURE/komari-agent-live"
fi
if [ "$component" = komari-host ] && [ -n "${KOMARI_INSTALLER_HOST_VARIANT:-}" ]; then
    source="$KOMARI_INSTALLER_FIXTURE/komari-host-$KOMARI_INSTALLER_HOST_VARIANT"
fi
printf '%s\n' "$url" >> "$KOMARI_INSTALLER_REQUEST_LOG"
if [[ "$url" = *.sha256 ]]; then
    if [ "${KOMARI_INSTALLER_BAD_HASH:-}" = "$component" ]; then printf '%064d  fixture\n' 0; else sha256sum "$source"; fi
else
    [ -n "$output" ]
    cp "$source" "$output"
fi
CURL
sudo install -m 755 "$log_dir/curl" "$fixture/mock-bin/curl"
run_installer() {
    local unit="$1"; shift
    local register_mode="${KOMARI_INSTALLER_REGISTER_ONLY:-true}"
    local installer_flags=(--install-service-name "$unit" \
        --install-dir "/usr/lib/komari/$unit" \
        --install-version "${KOMARI_INSTALLER_VERSION:-fixture}" \
        --endpoint https://panel.invalid)
    if [ "$register_mode" = true ]; then installer_flags+=(--install-register-only); fi
    sudo env PATH="$fixture/mock-bin:$PATH" KOMARI_INSTALLER_FIXTURE="$fixture" \
        KOMARI_INSTALLER_BAD_HASH="${bad_hash:-}" \
        KOMARI_INSTALLER_BAD_BINARY="${bad_binary:-}" \
        KOMARI_INSTALLER_LIVE_BINARY="${live_binary:-}" \
        KOMARI_INSTALLER_HOST_VARIANT="${host_variant:-}" \
        KOMARI_INSTALLER_REQUEST_LOG="$log_dir/release-requests.log" \
        bash "$root/install.sh" "${installer_flags[@]}" "$@"
}
expect_rejected() {
    local scenario="$1"; shift
    if "$@"; then echo "FAIL: $scenario was accepted" >&2; exit 1; fi
    echo "PASS: $scenario rejected"
}

# A pristine account must not own the shared state parent. Use the actual
# install.sh entry point and host binary, not an extracted/mock install method.
if id -u komari >/dev/null 2>&1; then echo 'Unexpected pre-existing fixture account' >&2; exit 1; fi
run_installer "$pristine"
test "$(getent passwd komari | cut -d: -f6)" = /nonexistent
test "$(sudo stat -c '%u:%g:%a' /var/lib/komari)" = 0:0:755
for command in python3 curl flock runuser useradd; do
    sudo bash -c 'command -v "$1" >/dev/null' bash "$command"
done
sudo test -x /usr/bin/pamtester
sudo -u komari test -w "/var/lib/komari/$pristine"
sudo -u komari test ! -w "/usr/lib/komari/$pristine/komari-host"
for path in /etc/komari /etc/komari/services "/usr/lib/komari/$pristine"; do
    test "$(sudo stat -c '%u:%g:%a' "$path")" = 0:0:755
done
# Execute the real ELF and read registry/bootstrap metadata as the daemon user.
# A root-only Host diagnose cannot detect mode-0700 public directories.
sudo -u komari "/usr/lib/komari/$pristine/komari-agent" config show --json > "$log_dir/pristine-config.json"

# Updating a registered node replaces reviewed binaries while preserving its
# identity, service account, policy and systemd definition.
printf '{"agent_id":"00000000-0000-4000-8000-000000000001","endpoint":"https://panel.invalid"}\n' \
    | sudo -u komari tee "/var/lib/komari/$pristine/credentials.json" >/dev/null
sudo chmod 600 "/var/lib/komari/$pristine/credentials.json"
sudo sha256sum "/var/lib/komari/$pristine/credentials.json" \
    "/etc/komari/services/$pristine.json" "/etc/komari/services/$pristine.policy.json" \
    "/etc/systemd/system/$pristine.service" > "$log_dir/registered-before.sha256"
run_installer "$pristine"
sudo sha256sum -c "$log_dir/registered-before.sha256"
sudo cmp "$fixture/komari-agent" "/usr/lib/komari/$pristine/komari-agent"
sudo cmp "$fixture/komari-host" "/usr/lib/komari/$pristine/komari-host"
test "$(sudo systemctl show "$pristine" --property=User --value)" = komari
echo 'PASS: registered node updated with credentials, policy, service identity and unit preserved'

# A target Host that cannot read the current installation must be rejected
# before either binary or any registration/state file changes.
printf '#!/bin/sh\necho "fixture: incompatible host" >&2\nexit 42\n' > "$log_dir/komari-host-incompatible"
sudo install -m 755 "$log_dir/komari-host-incompatible" "$fixture/komari-host-incompatible"
sudo sha256sum "/usr/lib/komari/$pristine/komari-agent" "/usr/lib/komari/$pristine/komari-host" > "$log_dir/incompatible-before.sha256"
host_variant=incompatible
KOMARI_INSTALLER_VERSION=incompatible-downgrade \
    expect_rejected 'incompatible downgrade' run_installer "$pristine"
unset host_variant
sudo sha256sum -c "$log_dir/incompatible-before.sha256"
sudo sha256sum -c "$log_dir/registered-before.sha256"
echo 'PASS: incompatible downgrade refused before installed files changed'

# Exercise a requested downgrade that installs an ELF but cannot stay running.
# The installer must restore both binaries and return the active service to its
# exact pre-update executable; the fixture never contacts the panel.
printf '#!/bin/sh\nexec sleep 300\n' > "$log_dir/komari-agent-live"
sudo install -m 755 "$log_dir/komari-agent-live" "/usr/lib/komari/$pristine/komari-agent"
cat > "$log_dir/komari-agent-bad.go" <<'GO'
package main
import "os"
func main() { os.Exit(23) }
GO
GOMAXPROCS=2 go build -p=2 -o "$log_dir/komari-agent-bad" "$log_dir/komari-agent-bad.go"
sudo install -m 755 "$log_dir/komari-agent-bad" "$fixture/komari-agent-bad"
# Appending data preserves ELF execution while making the target Host differ
# from the installed one, so the rollback assertion verifies both replacements.
cp ci-artifacts/komari-host "$log_dir/komari-host-changed"
printf '\ninstaller-fixture-target-host\n' >> "$log_dir/komari-host-changed"
sudo install -m 755 "$log_dir/komari-host-changed" "$fixture/komari-host-changed"
sudo systemctl start "$pristine.service"
sudo systemctl is-active --quiet "$pristine.service"
sudo sha256sum "/usr/lib/komari/$pristine/komari-agent" "/usr/lib/komari/$pristine/komari-host" > "$log_dir/rollback-before.sha256"
bad_binary=true
host_variant=changed
KOMARI_INSTALLER_REGISTER_ONLY=false KOMARI_INSTALLER_VERSION=downgrade-fixture \
    expect_rejected 'unhealthy downgrade rolls back both binaries' run_installer "$pristine" --install-metrics-only
unset bad_binary
unset host_variant
sudo sha256sum -c "$log_dir/rollback-before.sha256"
sudo systemctl is-active --quiet "$pristine.service"
echo 'PASS: failed downgrade restored both previous binaries and restarted the service'

# A promoted service keeps its original account in the manifest, but has
# root-owned credentials. Update using the actual systemd User, then exercise
# full host setup with explicit public pins and dependencies installed above.
sudo systemctl stop "$pristine.service"
sudo install -d -m 755 "/etc/systemd/system/$pristine.service.d"
printf '[Service]\nUser=root\nGroup=root\n' | sudo tee "/etc/systemd/system/$pristine.service.d/50-fixture-root.conf" >/dev/null
sudo chown -R root:root "/var/lib/komari/$pristine"
sudo systemctl daemon-reload
sudo systemctl start "$pristine.service"
sudo sha256sum "/var/lib/komari/$pristine/credentials.json" "/etc/komari/services/$pristine.json" \
    "/etc/systemd/system/$pristine.service" > "$log_dir/root-state-before.sha256"
cat > "$log_dir/komari-agent-live.go" <<'GO'
package main
import "time"
func main() { time.Sleep(5 * time.Minute) }
GO
GOMAXPROCS=2 go build -p=2 -o "$log_dir/komari-agent-live-elf" "$log_dir/komari-agent-live.go"
sudo install -m 755 "$log_dir/komari-agent-live-elf" "$fixture/komari-agent-live"
live_binary=true
host_variant=changed
KOMARI_INSTALLER_REGISTER_ONLY=false run_installer "$pristine" \
    --install-panel-key-id fixture --install-panel-public-key Bii7plda32t+iJAWXT2zBoy3uOiUuLqZa8dLqwmBQ6o= \
    --install-host-service-user komari
unset live_binary host_variant
sudo sha256sum -c "$log_dir/root-state-before.sha256"
# Credentials, original account and service identity must still be preserved.
sudo python3 - "$pristine" <<'CHECK'
import json, sys
service = sys.argv[1]
with open('/etc/komari/services/' + service + '.json') as f:
    manifest = json.load(f)
assert manifest['service_user'] == 'komari'
with open('/var/lib/komari/' + service + '/credentials.json') as f:
    identity = json.load(f)
assert identity['agent_id'] == '00000000-0000-4000-8000-000000000001'
CHECK
test "$(sudo systemctl show "$pristine" --property=User --value)" = root
sudo cmp "$fixture/komari-agent-live" "/usr/lib/komari/$pristine/komari-agent"
sudo cmp "$fixture/komari-host-changed" "/usr/lib/komari/$pristine/komari-host"
sudo "/usr/lib/komari/$pristine/komari-host" diagnose --manifest "/etc/komari/services/$pristine.json" \
    | tee "$log_dir/root-host-readiness.log"
grep -qx 'host_actions_ready=true' "$log_dir/root-host-readiness.log"
sudo systemctl is-active --quiet "$pristine.service"
sudo systemctl stop "$pristine.service"
sudo sha256sum "/var/lib/komari/$pristine/credentials.json" \
    "/etc/komari/services/$pristine.json" "/etc/komari/services/$pristine.policy.json" \
    "/etc/systemd/system/$pristine.service" > "$log_dir/registered-before.sha256"
echo 'PASS: promoted root service updated, credentials retained and full host prerequisites ready'

# Reproduce migration of an active non-root legacy service under the
# installer's umask 077, without precreating its destination binary directory.
sudo install -d -o komari -g komari -m 700 "$legacy_dir"
sudo install -m 755 "$fixture/komari-agent-live" "$legacy_dir/agent"
printf '{"agent_id":"00000000-0000-4000-8000-000000000002","endpoint":"https://panel.invalid"}\n' \
    | sudo -u komari tee "$legacy_dir/credentials.json" >/dev/null
printf '{"current":{"revision":4,"report_interval":3000000000}}\n' \
    | sudo -u komari tee "$legacy_dir/runtime-config.json" >/dev/null
printf '{"applied_revision":0}\n' | sudo -u komari tee "$legacy_dir/privileged.json" >/dev/null
printf '{}\n' | sudo -u komari tee "$legacy_dir/nonces.json" >/dev/null
legacy_state_paths=("$legacy_dir/credentials.json" "$legacy_dir/runtime-config.json" "$legacy_dir/privileged.json" "$legacy_dir/nonces.json")
sudo chmod 600 "${legacy_state_paths[@]}"
sudo sha256sum "${legacy_state_paths[@]}" > "$log_dir/legacy-state-before.sha256"
sudo tee "/etc/systemd/system/$legacy.service" >/dev/null <<UNIT
[Service]
User=komari
WorkingDirectory=$legacy_dir
ExecStart=$legacy_dir/agent --endpoint https://panel.invalid --credentials-file $legacy_dir/credentials.json --runtime-state-file $legacy_dir/runtime-config.json --privileged-state-file $legacy_dir/privileged.json --replay-state-file $legacy_dir/nonces.json --disable-remote-control --interval 12
Restart=on-failure
RestartSec=5
UNIT
sudo systemctl daemon-reload
sudo systemctl start "$legacy.service"
sudo test ! -e "/usr/lib/komari/$legacy"
run_installer "$legacy"
sudo -u komari "/usr/lib/komari/$legacy/komari-agent" config show --json > "$log_dir/legacy-config.json"
python3 - "$log_dir/legacy-config.json" <<'CHECK'
import json, sys
with open(sys.argv[1]) as f:
    config = json.load(f)
assert config['runtime']['revision'] == 4
assert config['local_config']['disable_remote_control'] is True
CHECK
sudo sha256sum -c "$log_dir/legacy-state-before.sha256"
sudo sha256sum "/etc/komari/services/$legacy"*.json \
    "/etc/systemd/system/$legacy.service" \
    "/etc/systemd/system/$legacy.service.d/90-komari-trusted-layout.conf" \
    > "$log_dir/legacy-registration-before.sha256"
echo 'PASS: non-root legacy migration executes real Agent CLI and preserves revision and local restrictions'

# A rerun must repair directories left at 0700 by the old installer without
# changing private file modes, trust, service identity, or node state. Restart
# a real ELF fixture as komari so systemd would expose the reported 203/EXEC.
sudo chmod 700 /usr/lib/komari "/usr/lib/komari/$legacy" /etc/komari /etc/komari/services
if sudo -u komari test -x "/usr/lib/komari/$legacy/komari-agent"; then
    echo 'FAIL: inaccessible migration fixture is executable' >&2; exit 1
fi
live_binary=true
KOMARI_INSTALLER_REGISTER_ONLY=false run_installer "$legacy" --install-metrics-only
unset live_binary
sudo sha256sum -c "$log_dir/legacy-state-before.sha256"
sudo sha256sum -c "$log_dir/legacy-registration-before.sha256"
test "$(sudo systemctl show "$legacy" --property=User --value)" = komari
sudo systemctl is-active --quiet "$legacy.service"
legacy_pid=$(sudo systemctl show "$legacy" --property=MainPID --value)
test "$(sudo readlink "/proc/$legacy_pid/exe")" = "/usr/lib/komari/$legacy/komari-agent"
for path in /usr/lib/komari "/usr/lib/komari/$legacy" /etc/komari /etc/komari/services; do
    test "$(sudo stat -c '%u:%g:%a' "$path")" = 0:0:755
done
test "$(sudo stat -c '%a' "$legacy_dir")" = 700
for path in "${legacy_state_paths[@]}"; do test "$(sudo stat -c '%a' "$path")" = 600; done
test "$(sudo stat -c '%a' "/etc/komari/services/$legacy.migration-bootstrap.json")" = 640
sudo systemctl stop "$legacy.service"
echo 'PASS: prior mode-0700 migration repaired and systemd executes Agent as non-root with private state retained'

# Reproduce the reported host: mode-0700 komari home at the shared state
# parent, plus trusted binaries left behind by the failed original installer.
sudo usermod --home /var/lib/komari komari
sudo chown "$(id -u komari):$(id -g komari)" /var/lib/komari
sudo chmod 700 /var/lib/komari
printf 'preserve old home contents\n' | sudo -u komari tee /var/lib/komari/home-sentinel >/dev/null
sudo sha256sum /var/lib/komari/home-sentinel > "$log_dir/home-before.sha256"
sudo install -d -m 755 "/usr/lib/komari/$service"
for component in komari-agent komari-host; do
    printf 'leftover %s\n' "$component" | sudo tee "/usr/lib/komari/$service/$component" >/dev/null
    sudo chmod 755 "/usr/lib/komari/$service/$component"
done
sudo sha256sum "/usr/lib/komari/$service/komari-agent" "/usr/lib/komari/$service/komari-host" > "$log_dir/leftovers-before.sha256"

# Reject a bad SECOND download before replacing either leftover binary.
bad_hash=komari-host
expect_rejected 'second download checksum mismatch' run_installer "$service"
unset bad_hash
sudo sha256sum -c "$log_dir/leftovers-before.sha256"
sudo test ! -e "/etc/komari/services/$service.json"
sudo test ! -e "/var/lib/komari/$service"
test "$(sudo stat -c '%u:%g:%a' /var/lib/komari)" = 0:0:755

run_installer "$service"
sudo cmp "$fixture/komari-agent" "/usr/lib/komari/$service/komari-agent"
sudo cmp "$fixture/komari-host" "/usr/lib/komari/$service/komari-host"
sudo -u komari test -w "/var/lib/komari/$service"
sudo sha256sum -c "$log_dir/home-before.sha256"
sudo sha256sum -c "$log_dir/registered-before.sha256"
test "$(sudo stat -c '%u' /var/lib/komari/home-sentinel)" = "$(id -u komari)"
echo 'PASS: exact old-home collision and leftover-binary retry'

# Refuse existing unregistered state; never erase it to make installation pass.
sudo install -d -m 700 "/var/lib/komari/$service-orphan"
printf 'orphan node identity\n' | sudo tee "/var/lib/komari/$service-orphan/credentials.json" >/dev/null
sudo sha256sum "/var/lib/komari/$service-orphan/credentials.json" > "$log_dir/orphan-before.sha256"
expect_rejected 'unregistered node state' run_installer "$service-orphan"
sudo sha256sum -c "$log_dir/orphan-before.sha256"

# Parent symlinks, unknown owners, and a writable legacy home stay rejected.
sudo mv /var/lib/komari "$saved_parent"
sudo ln -s "$saved_parent" /var/lib/komari
expect_rejected 'symlink state parent' run_installer "$service-symlink"
sudo test -L /var/lib/komari
sudo unlink /var/lib/komari
sudo mv "$saved_parent" /var/lib/komari
sudo chown nobody /var/lib/komari
expect_rejected 'unknown state parent owner' run_installer "$service-owner"
test "$(sudo stat -c '%u' /var/lib/komari)" = "$(id -u nobody)"
sudo chown komari /var/lib/komari
sudo chmod 777 /var/lib/komari
expect_rejected 'writable legacy home' run_installer "$service-writable"
test "$(sudo stat -c '%a' /var/lib/komari)" = 777
sudo chown root:root /var/lib/komari
sudo chmod 755 /var/lib/komari

# A failed attempt may leave a regular trusted binary, never a link to adopt.
sudo install -d -m 755 "/usr/lib/komari/$service-binary-link"
sudo ln -s "$fixture/komari-agent" "/usr/lib/komari/$service-binary-link/komari-agent"
expect_rejected 'symlink leftover binary' run_installer "$service-binary-link"
sudo test -L "/usr/lib/komari/$service-binary-link/komari-agent"
echo 'PASS: installer recovery and existing trust boundaries'
