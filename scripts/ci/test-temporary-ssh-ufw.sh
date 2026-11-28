#!/usr/bin/env bash
# Use the installed UFW implementation with an isolated config and network.
set -euo pipefail
cd "$(dirname "$0")/../.."
stage=$(mktemp -d /tmp/komari-ufw-ci.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/bin" "$stage/etc/default" "$stage/etc/ufw/applications.d" "$stage/lib/ufw"
cp /usr/share/ufw/{before,after,user}{,6}.rules /usr/share/ufw/ufw.conf "$stage/etc/ufw/"
# Do not run the host's sysctl configuration as part of the test.
sed -e 's|^IPT_SYSCTL=.*|IPT_SYSCTL=|' -e 's|^IPV6=.*|IPV6=yes|' /etc/default/ufw > "$stage/etc/default/ufw"
export KOMARI_UFW_TEST_DATA="$stage"
cat > "$stage/bin/ufw" <<'EOF'
#!/usr/bin/env bash
exec /usr/sbin/ufw --rootdir=/ --datadir="$KOMARI_UFW_TEST_DATA" "$@"
EOF
chmod 0700 "$stage/bin/ufw"
export PATH="$stage/bin:$PATH"
bash scripts/ci/test-temporary-ssh-window.sh ufw
