# Trusted installation, stage 3

The service binary and short-lived `komari-host` are root-owned, under `/usr/lib/komari/<service>/`. Every parent directory is checked. Policy and service manifests are root-owned under `/etc/komari/services/`. Daemon state remains service-owned under `/var/lib/komari/<service>/`; host backups/journals are under `/var/lib/komari-host/<service>/`. Fresh installs include no rescue helper. Linux systemd is the only accepted installer; other platforms fail explicitly.

`komari-agent config show [--json]` and `status privileged` share the service resolver and show redacted persisted state. They do not report the CLI euid as the daemon identity. All subcommands read the same manifest and bootstrap JSON. A missing manifest on an installed service requires migration instead of silently reading root's HOME. `--service-manifest` selects an exact service; `--standalone` is explicit.

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

`upgrade` / `update-conf` share one deprecated command and only delegate to a trusted host tool. Legacy elevation scripts fail without reading passwords or mutating files. CLI rollback no longer writes daemon state. **Identity conversion and helper installation remain unavailable until stage 6**; `komari-host apply` returns an error and never claims success.

CI runs Go regressions, cross-compiles the host tool, and exercises fresh installation and legacy migration with real systemd metadata on a disposable runner. All output, including failures, is retained for 30 days. No production host is modified by development or CI.

Fresh installs currently use the standard state directory; custom state-file overrides are explicitly rejected before creating/chowning it. Legacy migration preserves custom state paths. Service IDs omit the `.service` suffix; passing a suffixed ID is rejected to avoid registering another unit. An existing policy or partial registration is never silently overwritten on retry: inspect its root journal/backup and repair explicitly. Host installation/migration is not yet the crash-recoverable identity/helper transaction promised in stage 6. The administrator-owned trust root needed by that future transaction must be added before enabling host actions; daemon credential keys alone will not authorize root execution.
