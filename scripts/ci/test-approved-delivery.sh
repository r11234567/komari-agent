#!/usr/bin/env bash
# Real root-owned policy + signed Connect transport; disposable Linux CI only.
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ]; then echo 'Disposable GitHub runner required' >&2; exit 1; fi
mkdir -p ci-artifacts
exec > >(tee ci-artifacts/approved-delivery.log) 2>&1
trap 'status=$?; echo "$status" > ci-artifacts/approved-delivery-exit.txt; exit "$status"' EXIT
service="komari-approved-${GITHUB_RUN_ID}"
policy="/etc/komari/services/$service.policy.json"
manifest="/etc/komari/services/$service.json"
sudo install -d -m 755 /etc/komari/services
sudo tee "$policy" >/dev/null <<POLICY
{"version":2,"service_id":"$service","privilege_mode":2,"allow_remote_control":true,"allow_webssh":true,"allow_execution":true,"allow_gpu":true,"force_deny_remote_control":false}
POLICY
sudo tee "$manifest" >/dev/null <<MANIFEST
{"version":2,"service_name":"$service","service_user":"runner","init_system":"systemd","host_policy_file":"$policy","credentials_file":"/unused","runtime_state_file":"/unused","privileged_state_file":"/unused","replay_state_file":"/unused"}
MANIFEST
sudo chmod 644 "$policy" "$manifest"
export KOMARI_TEST_APPROVAL_MANIFEST="$manifest"
export GOMAXPROCS=2
go test -p=2 -json -count=1 -timeout=3m -run '^TestApprovedDelivery' ./clientcore 2> >(tee ci-artifacts/approved-delivery-build.log >&2) | tee ci-artifacts/approved-delivery.jsonl
