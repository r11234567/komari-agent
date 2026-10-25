# Workspace OS accounts

Workspace assignments require an explicit OS username and workspace scope.
Unix Agents execute PTYs and stateful file workers as that user, including its
supplementary groups. The Agent process never changes its own UID. Child
environments exclude Agent tokens and configuration secrets.

A root Agent may select an existing non-root account. A non-root Agent can only
select itself. Set `KOMARI_WORKSPACE_USERS=alice,bob` in the Agent service to
restrict the available usernames. Root/UID 0 is refused unless its canonical
username appears explicitly in this machine-local allowlist. Do not expose an
allowlist setting through the remote panel. The Agent binary and its parent
directories must be executable/traversable by the selected account.

Windows account switching is not implemented: the workspace fails closed rather
than silently executing as the service account. Old Agents are rejected by the
server's workspace-identity handshake. Terminal-embedded legacy file commands
are disabled; file operations use the isolated FileService worker.

File workers are isolated per workspace authorization so transfers retain their
in-memory chunk state. Cancellation stops that workspace worker; concurrent
operations in it may also need retrying. Idle workers are reclaimed. This does
not add ACL/xattr/hard-link metadata preservation.

For upload/download streams, a parent-owned loopback relay exposes only one
fixed transfer to the worker and closes with that request. The parent keeps
the long-lived Agent token, uses the existing authenticated data-plane route,
and never sends its config or credential-bearing upstream URLs to the child.

All tests/builds run on GitHub-hosted Actions. The focused identity checkpoint
checks actual root-to-nonroot filesystem permissions, as well as race tests,
without starting the complete panel or running E2E. Logs are always uploaded.
