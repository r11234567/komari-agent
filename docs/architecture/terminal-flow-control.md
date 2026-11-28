# Terminal sender pressure and process lifecycle

The Connect terminal keeps its bounded 32-by-32-KiB output queue. Command
acknowledgments use a separate coalesced signal and the latest accepted cursor;
they do not block the command receiver behind queued output. A single sender
serializes frames and gives ACKs priority between output sends. An already
blocked network write still depends on cancellation or receiver progress.

Non-retryable failure or authorization expiry cancels the session, including
quiet Receive. Transient transport failure follows the bounded resumption
procedure below. Final cancellation closes the PTY, and cleanup joins sender,
reader and process-wait workers. Close events follow the successfully read
output tail. Unix process waiting is shared by
Wait/Close and the PTY descriptor is released after both cancellation and natural
exit. Local capability revocation retains its existing polling deadline.

Regressions use a stalled synthetic transport, real bounded queues, multiple
interrupts/resize, output-tail sequencing, send failures and idle local
revocation. Real Unix PTYs cover descriptor and process-reaper cleanup. The
existing OS user selection and local root allowlist are unchanged. No legacy
terminal/file fallback is introduced.

## Checkpointed transport resumption (2026-11-04)

The Agent now owns one PTY for the lifetime of one authorized terminal session,
rather than the lifetime of an individual HTTP/2 request. A temporary transport
failure retries the same assignment/session identity. The backend sends its
accepted output cursor and an authorization-bounded retention deadline before
any replay. The Agent keeps at most 32 unconfirmed output frames of up to 32 KiB
each, in addition to the existing bounded reader queue; backpressure stops
unbounded allocation. Only unconfirmed events are replayed. The applied command
cursor stays with the PTY, so a repeated input/resize sequence cannot execute a
second time.

Each backend checkpoint permits at most 30 seconds of offline retention and is
capped by the original workspace idle and absolute deadlines. Heartbeats never
renew human authorization. Expiry, capability revocation, permission errors,
unknown sessions or lost backend replay state close the original PTY. A backend
process restart is therefore a terminal-session failure, not a promise of
persistent shells. This is terminal resumption, not file-transfer resumption.

The paired backend and Agent must both support the additive protocol fields.
An unsupported backend fails explicitly and closes the PTY; no new shell is
silently started to impersonate the old session. A legacy Agent that loses its
transport is closed explicitly by the new backend instead of being reassigned.

Local evidence: Linux Go race tests passed for clientcore and terminal. Ten
repetitions of the resumption cases passed, including an actual `/bin/sh` PTY
with identical PID and working directory before, during and after disconnection,
retained offline output, replayed-command rejection, bounded buffering and
expiry. These tests use isolated transport peers and do not claim deployed
Debian/Nginx end-to-end acceptance.

Deploy the updated Agent together with the backend for the complete behavior.
The panel's buffer limits and actual Debian/Docker/Nginx acceptance checklist
are documented in the backend repository. This fix does not prove that every
previous cold-start delay had the same cause as the earlier DNS/dial fix.

## Proxy-restart EOF and silent-transport repair (2026-11-04)

The first resumption dev incorrectly treated Connect's locally generated
`internal: protocol error: incomplete envelope: unexpected EOF` as a permanent
failure. A severed HTTP/2 connection therefore closed the PTY instead of
retrying it. The classifier now follows the wrapped EOF/closed-pipe/network
cause while retaining explicit authorization, state-loss, resource and protocol
failures as terminal. Server-sent Internal/Unknown errors do not become retryable
because their text resembles a socket failure.

The ten-second opening deadline now covers dialing and the first Send as well
as the first Receive. After attachment, twelve seconds without a valid backend
checkpoint cancels only the current HTTP request and retries within the existing
retention lease. It does not cancel the PTY or extend authorization. A temporary
silent/half-open route can no longer occupy the entire thirty-second retention
window without a new attempt. The backend heartbeat interval remains five seconds.

Agent logs record the session, attachment attempt, accepted cursors, interruption
code and retry decision. Terminal input, output and credentials are not logged.

The regression severs a real TLS/HTTP2 connection while a real `/bin/sh` is
running and verifies the same PID/directory after reattachment. Additional tests
cover authoritative HTTP/2 rejections, silent peers and stalled opening. This
reproduces the observed EOF without claiming a deployed Xray/Nginx acceptance
result. A disconnect around the original three-minute idle deadline still ends
an idle grant; transport recovery must not bypass that deadline.
