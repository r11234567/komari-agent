# Recovery commands

`komari-agent recover` is a short-lived, local recovery tool. It shares only the persisted runtime-config core with the daemon and never starts a second monitoring process.

Allowed actions are `version`, `verify --file PATH --sha256 HEX`, and `diagnostics`. There is intentionally no generic command runner. Output is capped at 64 KiB; the wrapper scripts impose a 30-second timeout by default.

Use `scripts/recover.sh` on Linux and `scripts/recover.ps1` on Windows. Set `KOMARI_AGENT_SHA256` before running either wrapper to require a checksum match for the executable. The commands do not elevate privileges: a Linux non-root or Windows standard-user process reports its limitations rather than attempting elevation.

Configuration queries use `komari-agent config show [--json]`. The former `recover show-config` and `recover rollback-config` commands and wrapper actions have been removed. Diagnostics report persisted data and do not identify the querying process as the daemon.
