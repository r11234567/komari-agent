#!/usr/bin/env bash
# Compile the production host/daemon packages and their tests without executing
# them. Single concurrency keeps this usable on small development machines.
set -euo pipefail
mkdir -p "${KOMARI_TEST_LOG_DIR:-ci-artifacts/stage6-compile}"
log_dir="${KOMARI_TEST_LOG_DIR:-ci-artifacts/stage6-compile}"
exec > >(tee "$log_dir/compile.log") 2>&1
trap 'status=$?; echo "$status" > "$log_dir/exit-code.txt"' EXIT
export GOMAXPROCS=1 GOMEMLIMIT=96MiB GOGC=30
go test -p=1 -vet=off -run '^$' ./cmd ./cmd/flags ./core/runtimeconfig ./core/hostops ./internal/hostcmd ./clientcore ./rescue
