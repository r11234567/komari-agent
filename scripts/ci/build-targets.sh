#!/usr/bin/env bash
# Build the Agent, rescue helper and Host from the same revision for one OS.
set -euo pipefail
: "${GOOS:?}" "${TARGET_ARCHES:?}" "${VERSION:?}"
mkdir -p ci-artifacts
extension=""
if [[ "$GOOS" == windows ]]; then extension=.exe; fi

for arch in $TARGET_ARCHES; do
  export GOARCH="$arch"
  dir="build/$GOOS-$arch"
  suffix="$GOOS-$arch$extension"
  mkdir -p "$dir"
  (
    set -e
    go build -trimpath -ldflags="-X github.com/komari-monitor/komari-agent/update.CurrentVersion=$VERSION" -o "$dir/komari-agent-$suffix" .
    go build -trimpath -ldflags="-X github.com/komari-monitor/komari-agent/update.CurrentVersion=$VERSION" -o "$dir/komari-agent-rescue-$suffix" ./cmd/komari-agent-rescue
    go build -trimpath -ldflags="-X github.com/komari-monitor/komari-agent/internal/hostcmd.ReleaseVersion=$VERSION" -o "$dir/komari-host-$suffix" ./cmd/komari-host
    cd "$dir"
    for binary in "komari-agent-$suffix" "komari-agent-rescue-$suffix" "komari-host-$suffix"; do
      sha256sum "$binary" > "$binary.sha256"
    done
  ) > >(tee "ci-artifacts/build-$GOOS-$arch.log") 2>&1
done
