# Linux host transactions (stage 6)

This development implementation supports Linux with systemd only. The host tool and daemon are separate processes; a root CLI never establishes that the daemon runs as root. Windows, macOS and FreeBSD do not advertise host actions. Cross compilation is not host-operation acceptance.

## Local preparation

Stage 3 installation/migration installs root-owned binaries and service metadata. It does not install the full rescue helper. Before enabling host actions, install the distribution `pamtester` package. The host tool uses the fixed `/etc/pam.d/komari-host` profile requiring `pam_unix` authentication and account checks, including when invoked as root. The password goes directly between the controlling terminal and PAM; the daemon, panel, RPC messages, argv, environment and logs never carry it.

A local administrator must independently verify and pin panel signing keys and the node UUID. Daemon enrollment TOFU keys are not automatically root authority. For an existing non-root service:

```sh
sudo komari-host trust --manifest /etc/komari/services/SERVICE.json \
  --endpoint https://PANEL --agent-id UUID \
  --panel-key-id VERIFIED_ID --panel-public-key VERIFIED_BASE64_KEY \
  --release-key-id PUBLISHER_ID --release-public-key PUBLISHER_BASE64_KEY
```

A service initially installed as root must also specify `--service-user ORIGINAL_NON_ROOT_ACCOUNT`; this account is the demotion target. Pinning trust never changes service identity. Restart the daemon explicitly after preparation so it negotiates the installed host actions; this development work does not restart production services automatically.

For Cloudflare Access, create a root-owned mode 0600 JSON file in a protected directory, containing `cf_access_client_id` and `cf_access_client_secret`. Pass its absolute path as `trust --access-config PATH`. The public trust file contains the path, not the secret. Configure the daemon's own local connection settings as well. Host redirects and insecure TLS are not allowed. This is local transport configuration, not authority to grant privileges.

## Apply and recover

The panel first saves a new revision and obtains fresh 2FA approval. The host tool then requires fresh local PAM authentication and rechecks the current signed approval before claiming and executing its lease:

```sh
sudo komari-host apply --manifest /etc/komari/services/SERVICE.json --revision N
sudo komari-host resume --manifest /etc/komari/services/SERVICE.json
sudo komari-host restore --manifest /etc/komari/services/SERVICE.json
```

The host tool validates full signatures, agent/service binding, approval generation, hash, action set, nonce, expiry and signed operation lease. It stops the actual service, fences reviewed state roots onto fresh root-owned inodes, writes a canonical service profile, restarts it, and checks real PID/UID, capability bounding/effective sets and NoNewPrivileges. It preserves credentials, UUID, runtime revisions and the safe original working directory. Arbitrary environment overrides, unsafe state parents, nested state roots, links, mounts and special files require an explicit local migration rather than automatic conversion.

An upgraded legacy installation may retain `force_deny_remote_control=true`
with `disable_source=legacy-unknown-preserve`. When the current signed host task
requests remote control, the normal `apply` command offers a local review:
type `authorize SERVICE REVISION`, then complete fresh PAM authentication. No
server change or hand-editing of JSON is required. The release of this historical
restriction is recorded in the root-owned transaction and committed with the
approved profile; rollback restores the previous restriction. Declining, failed
authentication or changed approval leaves it intact. Explicit local denies and
all other ceilings remain enforced. Rescue and ordinary remote control may be
enabled together with independent authorization. Ceiling errors identify the requested field and blocking
policy key instead of returning only a generic message.

The root profile clears the non-root NoNewPrivileges/capability ceiling. The non-root profile uses the original service account, NoNewPrivileges and CAP_NET_RAW. The root-owned policy constrains daemon snapshots during the restart window. A host LOCAL_APPLIED receipt is not final completion: the daemon must load the revision, independently observe its identity/helper and send its own immutable acknowledgement.

`/var/lib/komari-host/SERVICE/transaction.json` (journal schema 3) records state before mutation. It includes backed-up contents and UID/GID/mode; copies and ownership restoration account for newly created state files. Starting restoration first records `restoring`, so interruption cannot re-enter a success path. Restore works locally without needing network connectivity; its recovery receipt is retried later with the same ID and bytes. Superseded success receipts remain in the protected journal for diagnosis. Successful/recovered journals and backups are archived as whole directories; they are not deleted.

Legacy state directories may also contain a retired Agent executable. State fencing copies regular files through bounded streams (256 MiB per file, 512 MiB per transaction, at most 512 entries and eight directory levels), preserving the fresh-inode barrier against old writable file descriptors without loading entire binaries into memory. Limit errors identify the path before changing that file's metadata. The optional `fence_stage` journal field records `sealing` before the initial fence and `profile` before any target profile is published. An initial fencing failure restores recorded ownership/modes without repeating the failed copy. Legacy journals without this marker, and transactions that reached profile publication, still fence fresh inodes during restoration. A completed `restore` prints a success message only after service verification, accepted recovery receipt, and journal archival.

An unclaimed operation can only be archived automatically when there were no mutations and the panel explicitly reports it does not exist. Transport/database errors never prove absence. Expired or superseded grants cannot continue increasing privileges; use local recovery. A completed phase-3 operation may be read after expiry solely to reconcile acknowledgements; its original execution lease is never extended.

If an administrator restores after the panel already received the daemon ACK but its response was lost, the panel records RESTORED/failed while retaining its historical applied pointer. The old success cannot be replayed to re-enable the task. Use a new approved revision to reconcile future changes; recovery does not manufacture an applied old revision.

## On-demand rescue helper

The helper is a separate root service, never a setuid daemon or a local arbitrary-command socket. Installing it does not elevate the ordinary daemon: a non-root Agent remains non-root unless the administrator separately selects a different Agent target identity. Rescue and ordinary remote control can be enabled together; each keeps its own policy and signed authorization gates. Save the desired settings, confirm the revision with panel 2FA, then run the single command shown by the panel:

```sh
sudo komari-host apply --manifest /etc/komari/services/SERVICE.json --revision N
```

Apply explains the separate root rescue service before local PAM authentication. After authentication, it automatically downloads the exact version embedded in the root-owned Host binary from the fixed publisher repository, verifies the pinned publisher signature, platform and SHA-256, and only then claims a transaction and stops the original service. Download/signature failures leave the original service running and do not consume the approval. A matching verified cache avoids downloading again. A valid older cache is refreshed; a corrupt cache fails with a diagnostic. The panel/Agent cannot supply a download URL or choose the release version.

No prior `--install-rescue`, `fetch-helper`, or `allow_rescue_helper=true` is required. `allow_rescue_helper` records local consent and is granted inside the backed-up transaction after fresh PAM authentication for the signed install action. Explicit protected `force_deny_rescue_helper=true` prevents capability advertisement and installation; fresh trust setup can set it with `--deny-rescue-helper`. The daemon and rescue authorization gates enforce this deny too. Root-owned release keys and PAM setup remain prerequisites.

`fetch-helper --version EXACT_RELEASE_TAG` remains optional prefetch. Offline artifacts require both `--helper-artifact` and `--release-manifest`; they are independently verified, and starting an operation still requires an online currentness/lease check. Locally built Host binaries without an embedded release require these explicit artifacts. No fetched shell script is executed.

The helper independently checks current signed authorization and signed rescue tasks. It withdraws authorization and cancels managed actions when the signed target revokes it or validation/connectivity fails. A pending/unapproved configuration or unavailable panel at startup keeps the installed service idle: its process and heartbeat remain available, but authorization/lease readiness are false and no rescue tasks are leased or executed. A genuinely valid signed approval restores readiness automatically. Root-owned fresh heartbeat, PID start ticks, kernel UID and systemd cgroup are checked separately for installed/running/authorized/lease-ready status. A non-root daemon is not required to readlink a root process's `/proc/PID/exe`. Uninstallation is a separately approved host action.

The root helper creates and validates `/run/komari` on every startup, including legacy migrations and restarts after volatile `/run` is cleared. The directory is root-owned and mode 0755 so the ordinary Agent can read public heartbeat evidence. Existing symlinks, non-root ownership and writable directories are rejected rather than repaired. Initial heartbeat publication failure aborts startup with a specific error; recurring authorization or heartbeat errors are logged when they change. Host readiness timeout includes the last observation error. Real-systemd CI covers missing directories at first install and subsequent restart, unsafe paths, and retention of the ordinary Agent's non-root identity; runtime path metadata and public heartbeat evidence are retained with failure logs.

Automatic rollback archives the transaction only after the original service is verified and the panel confirms restoration. Receipt or archive failures retain the journal and print the explicit recovery command. `restore` also reconciles a fresh, signed `RESTORED` operation against the original journal authorization before archiving: older Hosts could clear an accepted receipt without archiving, then generate an illegal second terminal receipt on retry. Pending receipts remain in archived audit history. No backend relaxation of terminal state transitions is required.

Actual signed helper release publishing requires repository secret `KOMARI_RELEASE_SIGNING_KEY` (base64 Ed25519 private key, 64 bytes) and repository variable `KOMARI_RELEASE_SIGNING_KEY_ID`. The current publisher public key and ID are recorded in [`release-signing-key.json`](release-signing-key.json) and attached to stable releases. Release preflight verifies that the provisioned secret matches this reviewed public key before building any targets. The private key is provisioned once and reused; release jobs do not generate new keys.

The publisher key proves who produced a helper artifact. It is independent of each node's enrollment key and the panel's approval signing key. Node keys are generated during connection/enrollment and identify that node; they cannot authorize a publisher's software. Administrators must independently verify and pin the publisher public key locally with `--release-key-id` and `--release-public-key` before installing the helper. Downloading public metadata alone does not make it a trusted root. CI test keys cannot authorize production releases, and production publisher private keys never belong on nodes.

## Acceptance

`scripts/ci/test-host-transactions.sh` runs only on disposable GitHub runners. It covers first installation without prior rescue consent, corrupt-cache preparation failure with the non-root Agent still running, independent root helper readiness, and ordinary Agent identity preservation. It uses actual PAM, real daemon/host/helper binaries, actual systemd services, `/proc` observations and explicit network/process/startup faults. Only the panel is a fixture; its metrics and host-operation contracts must agree with the production API. Backend recovery and error-mapping tests separately exercise the real service/database implementation.

Failure artifacts include build errors, test output, journald/kernel logs and sanitized journal metadata, retained for 30 days. Raw credentials, state backups, signed authorization bundles and passwords are not exported. See the backend's `docs/privileged-stage6-failure-review.md` for the failure analysis. Stage 6 at source `9fe5463` passed complete acceptance in [run 39625269490](https://github.com/r11234567/komari-agent/actions/runs/39625269490), including actual PAM/systemd, promotion/demotion, helper lifecycle, lost receipts, process kills and restoration after a lost final daemon ACK. Subsequent CLI changes have their own regression checks; see [CLI migration](privileged-cli-migration-inventory.md).
