#!/usr/bin/env bash
# Disposable GitHub runner only: test install.sh with the real host tool.
# The downloads are local fixtures; no enrollment or production service is used.
set -Eeuo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ]; then echo 'Disposable GitHub runner required' >&2; exit 1; fi
root=$(pwd)
log_dir="$root/ci-artifacts/installer-recovery"
mkdir -p "$log_dir"
exec > >(tee "$log_dir/recovery.log") 2>&1
service="komari-installer-${GITHUB_RUN_ID}"
pristine="$service-pristine"
fixture="/usr/lib/komari/installer-fixture-${GITHUB_RUN_ID}"
saved_parent="/var/lib/komari-installer-parent-${GITHUB_RUN_ID}"
cleanup() {
    local status=$?
    trap - EXIT
    if sudo test -L /var/lib/komari && sudo test -d "$saved_parent"; then
        sudo unlink /var/lib/komari
        sudo mv "$saved_parent" /var/lib/komari
    fi
    for unit in "$service" "$pristine"; do
        sudo systemctl show "$unit" --property=ActiveState,SubState,Result > "$log_dir/$unit-status.log" 2>&1 || true
        sudo journalctl -u "$unit" --no-pager > "$log_dir/$unit-journal.log" 2>&1 || true
        sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    sudo namei -l /var/lib/komari > "$log_dir/state-parent.log" 2>&1 || true
    getent passwd komari > "$log_dir/service-account.log" || true
    printf '%s\n' "$status" > "$log_dir/exit-code.txt"
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
    sudo env PATH="$fixture/mock-bin:$PATH" KOMARI_INSTALLER_FIXTURE="$fixture" \
        KOMARI_INSTALLER_BAD_HASH="${bad_hash:-}" \
        bash "$root/install.sh" --install-service-name "$unit" \
        --install-dir "/usr/lib/komari/$unit" --install-version fixture \
        --endpoint https://panel.invalid "$@"
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
sudo -u komari test -w "/var/lib/komari/$pristine"
sudo -u komari test ! -w "/usr/lib/komari/$pristine/komari-host"

# Reject an already registered installation without changing node files.
printf '{"fixture":"preserve-node-id"}\n' | sudo -u komari tee "/var/lib/komari/$pristine/credentials.json" >/dev/null
sudo sha256sum "/var/lib/komari/$pristine/credentials.json" \
    "/usr/lib/komari/$pristine/komari-agent" "/usr/lib/komari/$pristine/komari-host" \
    "/etc/komari/services/$pristine.json" "/etc/komari/services/$pristine.policy.json" \
    "/etc/systemd/system/$pristine.service" > "$log_dir/registered-before.sha256"
expect_rejected 'registered service reinstall' run_installer "$pristine"
sudo sha256sum -c "$log_dir/registered-before.sha256"

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
