#!/usr/bin/env bash
# Run with root in a Linux VM or a dedicated container with isolated networking.
set -euo pipefail
cd "$(dirname "$0")/../.."
case "${1:-nftables}" in
  nftables) test_name=TestTemporarySSHWindowNftables ;;
  ufw) test_name=TestTemporarySSHWindowUFW ;;
  *) exit 2 ;;
esac
exec unshare --net -- bash -eu -o pipefail -c '
  unshare --net -- sleep infinity &
  peer=$!
  trap "kill $peer 2>/dev/null || true" EXIT
  for i in {1..50}; do
    if [[ $(readlink "/proc/$peer/ns/net") != "$(readlink /proc/self/ns/net)" ]]; then break; fi
    sleep 0.02
  done
  ip link set lo up
  ip link add sshhost type veth peer name sshpeer
  ip link set sshpeer netns "$peer"
  ip addr add 192.0.2.1/24 dev sshhost
  ip -6 addr add fd69:434f:4d41::1/64 dev sshhost nodad
  ip link set sshhost up
  nsenter -t "$peer" -n ip link set lo up
  nsenter -t "$peer" -n ip link set sshpeer up
  nsenter -t "$peer" -n ip addr add 192.0.2.2/24 dev sshpeer
  nsenter -t "$peer" -n ip addr add 192.0.2.3/24 dev sshpeer
  nsenter -t "$peer" -n ip -6 addr add fd69:434f:4d41::2/64 dev sshpeer nodad
  nsenter -t "$peer" -n ip -6 addr add fd69:434f:4d41::3/64 dev sshpeer nodad
  KOMARI_CREDENTIAL_ROOT_TEST=1 KOMARI_SSH_WINDOW_PEER_PID="$peer" go test -count=1 -timeout=1m -v ./rescue -run "^$1$"
' _ "$test_name"
