# QGA forensic sessions

QGA forensics observes the guest side of the installed QEMU guest-agent virtio channel on Linux. It follows matched execution and file-read requests and replies. It records the observed time, the command, the frame digest and any gaps in the capture. Request environment variables and stdin are omitted from retained frames. File contents appear only when QGA actually returned them through the observed channel. The scope excludes direct storage access by the hypervisor and files an invoked program accessed without returning their contents through QGA.

Start a session from a direct interactive root OpenSSH login on a host that already runs a root Komari Agent under systemd. The supported Komari host installation must have its PAM profile and protected panel trust in place. Copy the panel's X25519 recipient and Ed25519 receipt public keys through a verified administrative channel. The panel must allow submissions for the enrolled node and have a private archive directory outside the database.

```sh
komari-host qga-forensics \
  --manifest /etc/komari/services/komari-agent.json \
  --recipient-public-key "$RECIPIENT_PUBLIC_KEY" \
  --receipt-public-key "$RECEIPT_PUBLIC_KEY" \
  --duration 15m
```

PAM verifies the root password on the terminal. The session runs in the foreground and ends when its duration expires, the terminal sends hangup, the root Agent exits, or the receiver fails to acknowledge an upload. It seals each observation in memory and verifies the receipt returned by the panel. Restarting the Agent does not restart a forensic session. The kernel hooks and partial frames are cleared when the command exits. The panel records a separate signed reception time. Preserve the encrypted original archives and the independently verified receipt public key when exporting evidence.
