# CLI and configuration ownership inventory (stage 0)

This inventory records what later agent stages must change; this test-only
branch intentionally does not change runtime behavior.

| Surface | Current owner/use | Planned treatment |
| --- | --- | --- |
| endpoint/token, enrollment credentials, CF Access identity | Connection bootstrap/authentication | Keep; never expose credentials in config show/logs |
| config, runtime-state-file, privileged-state-file, credentials-file, replay-state-file | Service/path bootstrap | Keep, unified service manifest resolution |
| interval, memory-include-cache, NIC/mount filters, month-rotate | Runtime seed and delivered snapshot | Keep bootstrap purpose, applied snapshot takes precedence |
| get-ip-addr-from-nic | Startup flag OR persisted value | Fix override so remote false works |
| enable-gpu, detailed-gpu | Split privileged/runtime paths | Merge through EffectiveConfig, preserve dependency check |
| disable-remote-control | Installer bootstrap AND local prohibition conflated | Migrate proven installer defaults; preserve explicit force-deny |
| custom-dns, prefer-ip-version, info-report-interval, reconnect-interval, custom-ipv4/6 | Startup consumers; proto fields not fully wired | Implement supported delivery or explicitly reject |
| disable-auto-update | Startup update policy | Keep local policy; root-owned program updates require host tool |
| ignore-unsafe-cert | Weakens transport verification | Keep separate confirmation/local-policy rule |
| max-retries, disable-compression | No effective runtime consumer found in audit | Deprecate explicitly before removal; do not silently ignore unknown flags |
| auto-discovery/server-name | First registration | Keep bootstrap purpose |
| show-warning | Windows startup behavior | Keep platform scope |
| upgrade, update-conf | Duplicated privileged operation entry | One host-tool implementation, compatibility alias only |
| rollback vs recover rollback-config | Privileged policy vs ordinary snapshot recovery | Keep scopes distinct; widening rollback requires authorization |
| recover show-config | Persisted ordinary config only | Keep recovery use; implement canonical config show separately |
| status privileged | CLI identity currently mixed with daemon state | Report actual service/daemon identity and observation source |
| config show | Advertised in web but absent | Implement canonical read-only redacted view in CLI stage |
| UnknownFlags whitelist | Accepts typo/removed flags silently | Replace with explicit compatibility table |

The audit overlay covers the nine ordinary defects and one root/PTY defect.
Service manifest tests already present in cmd remain mandatory in CI. Program
ownership, OS authorization, actual service conversion and failure restoration
need dedicated tests when the host tool is implemented; a mocked root test
must never be presented as validating real PAM/systemd behavior.
