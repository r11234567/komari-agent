# Trusted installation, stage 3

The service binary and short-lived `komari-host` are root-owned, under `/usr/lib/komari/<service>/`. Every parent directory is checked. Policy and service manifests are root-owned under `/etc/komari/services/`. Daemon state remains service-owned under `/var/lib/komari/<service>/`; host backups/journals are under `/var/lib/komari-host/<service>/`. Fresh installs include no rescue helper. Linux systemd is the only accepted installer; other platforms fail explicitly.

The Linux systemd installer is also the administrator update entry point. Re-running `curl -fsSL https://raw.githubusercontent.com/r11234567/komari-agent/main/install.sh | sudo bash` detects a fresh installation, a registered v2 service, or a legacy service. Registered updates preserve the manifest, policy, unit, credentials and all daemon state; legacy services migrate conservatively with `--legacy-disable preserve`. Existing services retain their current account and local configuration; omit daemon arguments when updating. Only a previously active service is restarted. A registered update that fails its restart check attempts to restore the previous agent and host binaries and returns failure. `python3` is required to safely read a registered installation's JSON paths. Low-level host commands below remain available for explicit preview and manual control.

Both release binaries and checksums are downloaded and verified in a temporary root-owned directory before installed files change. A failed fresh attempt that left only trusted binaries can be retried. Existing node state without its service registration, partial policy/manifest registrations, unknown owners and symlinks remain explicit recovery cases; the installer does not erase them to make a retry pass. Uninstalling is not an update method: the old `/opt/komari` uninstaller can delete credentials stored there.

The service account has no created home (`/nonexistent`). `/var/lib/komari` is a root-owned, mode-0755 shared state parent; only `/var/lib/komari/<service>` belongs to the daemon account. Earlier scripts incorrectly created `/var/lib/komari` as the mode-0700 service-account home. A fresh retry repairs that exact owner/home collision without recursing into or rewriting existing contents. Other owner mismatches and writable/symlinked parents are rejected.

`komari-agent config show [--json]` uses the service resolver and shows redacted persisted state. It does not report the CLI euid as the daemon identity. All subcommands read the same manifest and bootstrap JSON. A missing manifest on an installed service requires migration instead of silently reading root's HOME. `--service-manifest` selects an exact service; `--standalone` is explicit.

Preview legacy migration locally:

```
sudo komari-host migrate --service custom-agent --legacy-disable preserve
```

Choose `preserve` or `release` explicitly after reviewing the old disable flag: its provenance cannot be inferred. To commit the preview, supply a root-owned new agent artifact and independently trusted release SHA-256:

```
sudo komari-host migrate --service custom-agent --legacy-disable preserve --agent-artifact /root/release/komari-agent-linux-amd64 --sha256 <digest> --commit
```

Migration reads the real systemd service, retains endpoint/arguments/custom state paths and service user, backs up effective unit sources, and installs the new binaries into a trusted directory. It does not rewrite node identity or revision files, re-enroll, restart, or mark pending tasks applied. Ambiguous command lines fail. Inspect the result and restart explicitly. Migration does not repair historical server approval errors or grant a new baseline to an old node.

Daemon self-update is disabled. Administrator updates use `komari-host update --manifest <path> --artifact <root-owned-binary> --sha256 <trusted-release-digest>`. The old binary and update phase are saved before atomic replacement; restarting and daemon verification are separate. An attacker-controlled checksum is not a trust root.

Public daemon update/elevation/rollback commands are removed. Legacy elevation scripts fail without reading passwords or mutating files. Approved identity conversion and helper installation use the separate, locally authenticated host flow described in [stage 6](privileged-host-stage6.md).

CI runs Go regressions, cross-compiles the host tool, and exercises fresh installation and legacy migration with real systemd metadata on a disposable runner. The public-script lifecycle suite additionally reproduces the legacy home collision and leftover binaries, verifies active updates preserve identity/configuration bytes, rejects checksum failures before mutation, recovers failed daemon updates, and checks symlink/owner refusal. Its small daemon fixture isolates installer orchestration; the separate PAM/systemd transaction suite tests the real daemon. All output, including failures, is retained for 30 days. No production host is modified by development or CI.

Fresh installs currently use the standard state directory; custom state-file overrides are explicitly rejected before creating/chowning it. Legacy migration preserves custom state paths. Service IDs omit the `.service` suffix; passing a suffixed ID is rejected to avoid registering another unit. An existing policy or partial registration is never silently overwritten on retry: inspect its root journal/backup and repair explicitly. Host installation/migration is not yet the crash-recoverable identity/helper transaction promised in stage 6. The administrator-owned trust root needed by that future transaction must be added before enabling host actions; daemon credential keys alone will not authorize root execution.
