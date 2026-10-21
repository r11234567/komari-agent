# Privileged delivery audit baseline (stage 0)

Run `python3 scripts/ci/run-privileged-audit.py` on a disposable Linux CI runner.
The script executes desired-invariant Go tests through an overlay; fixture files
are .txt so `go test ./...` does not treat four packages as one directory.

Nine ordinary invariants and one root/PTY invariant currently reproduce known
bugs. CI records the exact failure inventory. It rejects new failures, missing
cases, compiler errors, unexpected skips and newly passing cases that have not
yet been promoted to the mandatory regression suite. Every known failure is
emitted as a visible CI warning; full logs and inventory are artifacts.

As stages 3–6 fix each issue, move its test into the owning Go package and remove
its explicit known-failure entry in the same commit. The mandatory suite must
then pass that invariant. Do not broaden the expected-failure set to hide bugs.

All credentials, state and script paths are temporary synthetic fixtures.
Authentication, logging and systemctl commands are mocked in the root probe.
No live service, real host password or machine configuration is modified.
The root/PTY probe tests the CLI decision path, not real system authentication.
