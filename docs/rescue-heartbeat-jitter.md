# Rescue heartbeat jitter tolerance

The rescue helper receives signed authorization heartbeats every second. Public
Internet jitter can exceed the old two-second silence limit and cause the helper
to cancel its pending lease, producing Nginx 499 responses and repeated reconnects.

The helper now tolerates ten seconds measured from the last accepted frame's
signed issue time, not from its arrival. A frame aged ten seconds is rejected.
Replay, regressed sequence, invalid signature, explicit EOF/error, missing local
identity and local policy revocation still fail closed. Credential handoff does
not create a new authorization deadline. The security tradeoff is explicit:
during silent network failure, unseen revocation may take up to ten seconds to
stop authorization; an actual denial or disconnect does not wait ten seconds.

This change needs a new Agent/rescue binary. It does not require a panel or Nginx
configuration change and does not change AT/RT lifetimes.

CI runs the actual helper watch with protected root files and signed HTTP frames:
a 3.2-second pause stays on one connection; an aged resumed frame expires at its
original ten-second deadline; fresh frames recover; local denial and EOF revoke
within one second. A separate cursor test rejects replay and exact/beyond-limit
frames. A negative control restores the old two-second bound and must fail the
same runtime jitter assertion. All logs, exit codes and evidence remain uploaded
even on failure. Nothing is built or tested on the production VPS.
