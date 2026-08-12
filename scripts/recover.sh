#!/usr/bin/env sh
set -eu

agent_bin="${KOMARI_AGENT_BIN:-komari-agent}"
action="${1:-diagnostics}"
shift || true

case "$action" in
  version|verify|diagnostics|show-config|rollback-config) ;;
  *) echo "unsupported recovery action: $action" >&2; exit 64 ;;
esac

if [ -n "${KOMARI_AGENT_SHA256:-}" ]; then
  actual="$(sha256sum "$agent_bin" | awk '{print $1}')"
  if [ "$actual" != "$KOMARI_AGENT_SHA256" ]; then
    echo "agent checksum verification failed" >&2
    exit 65
  fi
fi

if command -v timeout >/dev/null 2>&1; then
  exec timeout "${KOMARI_RECOVER_TIMEOUT:-30}" "$agent_bin" recover "$action" "$@"
fi
exec "$agent_bin" recover "$action" "$@"
