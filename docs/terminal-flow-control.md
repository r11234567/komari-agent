# Terminal sender pressure and process lifecycle

The Connect terminal keeps its bounded 32-by-32-KiB output queue. Command
acknowledgments use a separate coalesced signal and the latest accepted cursor;
they do not block the command receiver behind queued output. A single sender
serializes frames and gives ACKs priority between output sends. An already
blocked network write still depends on cancellation or receiver progress.

Send failure cancels the session, including quiet Receive. The context closes
the PTY, and cleanup joins sender, reader and process-wait workers. Close events
follow the successfully read output tail. Unix process waiting is shared by
Wait/Close and the PTY descriptor is released after both cancellation and natural
exit. Local capability revocation retains its existing polling deadline.

Regressions use a stalled synthetic transport, real bounded queues, multiple
interrupts/resize, output-tail sequencing, send failures and idle local
revocation. Real Unix PTYs cover descriptor and process-reaper cleanup. The
existing OS user selection and local root allowlist are unchanged. No protocol
change or legacy terminal/file fallback is introduced.

Deploy the updated Agent together with the backend for the complete behavior.
The panel's buffer limits and actual Debian/Docker/Nginx acceptance checklist
are documented in the backend repository. This fix does not prove that every
previous cold-start delay had the same cause as the earlier DNS/dial fix.
