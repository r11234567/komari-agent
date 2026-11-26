#!/usr/bin/env bash
# Isolated, disposable Actions runners/containers only. Fixture signing keys
# replace the publisher key in a temporary copy of the installer.
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'Disposable CI environment required' >&2; exit 1; }

repo=$(cd "$(dirname "$0")/../.." && pwd)
binary=$1
fixture=$(mktemp -d /tmp/komari-monitoring-ci.XXXXXXXX)
chmod 755 "$fixture"
service=komari-monitoring-ci
case "$(uname -s)" in
    Linux)
        platform=linux
        agent_user=komari
        target='/opt/Komari installer CI'
        service_file="/etc/init.d/$service"
        as_root() { "$@"; }
        as_user() { runuser -u "$1" -- "${@:2}"; }
        status() { rc-service "$service" status; }
        stop() { rc-service "$service" stop; }
        ;;
    Darwin)
        platform=darwin
        agent_user=_komari
        target='/Library/Komari installer CI'
        service_file="/Library/LaunchDaemons/com.komari.$service.plist"
        as_root() { sudo env PATH="$PATH" "$@"; }
        as_user() { sudo -u "$1" "${@:2}"; }
        status() { as_root launchctl print "system/com.komari.$service" | grep -q 'state = running'; }
        stop() { as_root launchctl bootout "system/com.komari.$service"; }
        ;;
    *) exit 1 ;;
esac
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) exit 1 ;; esac
[ ! -e "$target" ] && [ ! -e "$service_file" ]
if id "$agent_user" >/dev/null 2>&1; then echo 'Unexpected preexisting fixture account' >&2; exit 1; fi
cleanup() {
    if [ -f "$service_file" ]; then
        stop >/dev/null 2>&1 || true
        if [ "$platform" = linux ]; then rc-update del "$service" default >/dev/null 2>&1 || true; fi
        as_root rm -f "$service_file"
    fi
    if [ "$platform" = linux ]; then as_root rm -f "/etc/komari/openrc/$service"; fi
    as_root rm -rf -- "$target" "$fixture"
}
trap cleanup EXIT

openssl genpkey -algorithm ED25519 -out "$fixture/publisher.pem"
chmod 600 "$fixture/publisher.pem"
key=$(openssl pkey -in "$fixture/publisher.pem" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')
sed "s|Bii7plda32t+iJAWXT2zBoy3uOiUuLqZa8dLqwmBQ6o=|$key|" "$repo/install.sh" > "$fixture/install.sh"
mkdir "$fixture/bin"
asset="komari-agent-$platform-$arch"
cp "$binary" "$fixture/$asset"
cat > "$fixture/bin/curl" <<'CURL'
#!/bin/bash
set -eu
[ "$#" -eq 4 ] && [ "$1" = -fsSL ] && [ "$2" = -o ]
case "$4" in
    "https://github.com/r11234567/komari-agent/releases/download/platform-fixture/"*)
        name=${4##*/}
        case "$name" in komari-agent-linux-*|komari-agent-darwin-*) ;; *) exit 22 ;; esac
        cp "$INSTALL_FIXTURE/$name" "$3"
        ;;
    *) exit 22 ;;
esac
CURL
chmod 755 "$fixture/bin/curl"
sign_asset() {
    python3 - "$fixture" "$asset" "$platform" "$arch" <<'PY'
import base64, hashlib, json, pathlib, subprocess, sys
folder, asset, platform, arch = sys.argv[1:]
root = pathlib.Path(folder)
payload = root / "payload.json"
payload.write_text(json.dumps(dict(schema="komari.release.v1", component="komari-agent",
    version="platform-fixture", os=platform, arch=arch,
    sha256=hashlib.sha256((root / asset).read_bytes()).hexdigest())))
signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-inkey", str(root / "publisher.pem"),
                                     "-rawin", "-in", str(payload)])
encode = lambda value: base64.b64encode(value).decode()
(root / (asset + ".release.json")).write_text(json.dumps(dict(
    key_id="komari-release-8372cfc532b8f1bf", payload=encode(payload.read_bytes()), signature=encode(signature))))
PY
}
args=(--install-service-name "$service" --install-dir "$target" --install-version platform-fixture
      --endpoint 'https://panel.invalid/?option=a&other=b')
install_agent() {
    as_root env "PATH=$fixture/bin:$PATH" "INSTALL_FIXTURE=$fixture" bash "$fixture/install.sh" "${args[@]}" "$@"
}
assert_rejected() {
    if "$@" > "$fixture/refused.log" 2>&1; then cat "$fixture/refused.log"; exit 1; fi
}

assert_rejected as_user nobody bash "$fixture/install.sh" "${args[@]}"
grep -q 'Run this installer as root' "$fixture/refused.log"
for flag in --install-rescue --install-runtime-identity; do
    extra=()
    if [ "$flag" = --install-runtime-identity ]; then extra=(root-or-administrator); fi
    assert_rejected install_agent "$flag" "${extra[@]}"
    grep -q 'Host privilege changes and rescue require Linux systemd' "$fixture/refused.log"
done
[ ! -e "$target" ] && [ ! -e "$service_file" ]
! id "$agent_user" >/dev/null 2>&1

sign_asset
install_agent
cmp "$binary" "$target/agent"
as_user "$agent_user" "$target/agent" recover version
as_user "$agent_user" test ! -w "$target/agent"
as_user "$agent_user" test ! -w "$service_file"
if [ "$platform" = linux ]; then as_user "$agent_user" test ! -w "/etc/komari/openrc/$service"; fi
as_user "$agent_user" test -w "$target/state"
if status >/dev/null 2>&1; then echo 'Unenrolled Agent started' >&2; exit 1; fi

# A signed process probe verifies the real supervisor/UID using disposable
# state. It does not enroll or contact an external panel.
cat > "$fixture/probe" <<'PROBE'
#!/bin/sh
set -eu
test "$(id -u)" -ne 0
printf '%s\n' "$@" > state/probe-argv
printf '%s\n' "$(id -u)" > state/probe-uid
printf '%s\n' "$$" > state/probe-pid
exec sleep 120
PROBE
cp "$fixture/probe" "$fixture/$asset"
sign_asset
as_user "$agent_user" sh -c 'umask 077; printf "{}\n" > "$1"' sh "$target/state/credentials.json"
install_agent --disable-remote-control=false
await_pid() {
    for attempt in $(seq 1 12); do
        if as_user "$agent_user" test -s "$target/state/probe-pid"; then
            as_user "$agent_user" cat "$target/state/probe-pid"
            return
        fi
        sleep 1
    done
    return 1
}
first_pid=$(await_pid)
status
[ "$(as_user "$agent_user" cat "$target/state/probe-uid")" = "$(id -u "$agent_user")" ]
as_user "$agent_user" grep -Fx 'https://panel.invalid/?option=a&other=b' "$target/state/probe-argv"
as_user "$agent_user" python3 - "$target/state/probe-argv" <<'PY'
import pathlib, sys
argv = pathlib.Path(sys.argv[1]).read_text().splitlines()
assert argv.index("--disable-remote-control=false") < argv.index("--disable-remote-control=true")
PY
as_user "$agent_user" rm -f "$target/state/probe-pid"
install_agent
second_pid=$(await_pid)
[ "$second_pid" != "$first_pid" ]
status
cmp "$fixture/probe" "$target/agent"
printf '\n' >> "$fixture/$asset"
assert_rejected install_agent
grep -q 'Release verification failed' "$fixture/refused.log"
cmp "$fixture/probe" "$target/agent"
status
[ "$(as_user "$agent_user" cat "$target/state/credentials.json")" = '{}' ]
echo "PASS: $platform signed install, protected files, nonroot supervisor, retained credentials and privilege/rescue denial"
