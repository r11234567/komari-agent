# Signed panel commands

Upgrade the panel before upgrading enrolled Agents. This Agent expects a paired
panel to sign WebSSH, file operations, ping and return-route probe instructions.
Telemetry and credential renewal use their existing RPCs. Connect and gRPC
carry the same signed instructions.

The Agent verifies commands with its pinned panel keys. WebSSH also verifies
each control frame against the challenge for the current attachment and its
frame number. File operations check the lease and the attachment separately.
The Agent persists one-time operation nonces before carrying out the operation.

Automatically managed trust updates require a signed response to a new Agent
challenge. Panel key changes must chain from the currently pinned key. An
installation with locally managed host trust follows the host's provisioning
procedure for changing its pin. An Agent without an existing panel pin must
enroll or provision that pin locally before background renewal can resume.
