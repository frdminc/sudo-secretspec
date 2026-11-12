# Encrypted vault backups (0.21.1-sudo.6+, macOS)

This downstream feature is **unreleased; requires 0.21.1-sudo.6 or later**.
The automated backup service currently supports macOS. Linux and NixOS backup
integration is not implemented; the backup CLI refuses on those platforms.

## What is protected (0.21.1-sudo.6+)

The backup captures the complete managed vault, including declarations,
`secrets.db`, `broker-audit.sqlite3`, and `broker-history.sqlite3` when present.
SQLite's backup API folds committed journal/WAL state into standalone database
images. The service verifies integrity and the audit chain, and rejects a capture
that changes while it is being assembled or contains an unresolved audit attempt.
An interrupted operation can leave an audit attempt unresolved indefinitely:
this is an operator-visible backup failure, never an excuse to invent an audit
outcome or replace the last good snapshot with incomplete data.

Every accepted changed snapshot is encrypted with `age` before being committed
to a dedicated local Git repository. The repository is separate from the vault
and from source control. A second machine holds an append-only bare Git copy.
There is no GitHub hosting requirement. Retained commits are not automatically
pruned; storage exhaustion produces a warning/failure, not history deletion.
Deleting or destroying a secret in the live vault does **not** erase it from
previous encrypted backups. Backups and their recovery keys are sensitive.

The root-owned launchd service captures at startup, hourly, and after debounced
filesystem changes. Parent-directory watches detect removal and recreation;
file watches detect content updates and replacement. Missing vaults generate an
incident and preserve the last valid backup. Backups do not recreate a missing
live vault. Replication retries independently after remote outages.

## Explicit setup (0.21.1-sudo.6+)

Package installation only ships files. It never edits sudoers, creates recovery
keys, enables services, or provisions a remote repository. Review the shipped
installer and choose an SSH destination before running setup explicitly:

```bash
# macOS; replace the operator, host, and remote path with your own values.
# Backup setup requires 0.21.1-sudo.6+ and administrator authentication.
sudo /usr/bin/python3 "$(brew --prefix sudo-secretspec)/share/sudo-secretspec/backup/install.py" \
  --operator YOUR_LOCAL_USER \
  --remote-host YOUR_BACKUP_HOST \
  --remote-repo /absolute/path/to/sudo-secretspec-history.git \
  --activate
```

The operator must already be able to authenticate to the remote host using SSH,
independently of credentials held in the vault being backed up. Verify the SSH
host key before setup. The installer creates a dedicated recovery identity
outside the vault and Git, copies it to a protected location on the second
machine, and verifies decryption with both copies. It provisions a separate
restricted SSH key for Git replication and refuses destructive remote updates.
Neither recovery identity belongs in Git, logs, command arguments, or chat.

Installed macOS paths (0.21.1-sudo.6+):

| Purpose | Path |
|---|---|
| Protected helper | `/usr/local/libexec/sudo-secretspec-backup/backup.py` |
| Protected configuration | `/usr/local/etc/sudo-secretspec-backup.json` |
| Local encrypted history and private state | `/var/db/sudo-secretspec-backup/` |
| Local recovery identity | `/var/root/.config/sudo-secretspec-backup/recovery.agekey` |
| Public non-secret health summary | `/usr/local/var/run/sudo-secretspec-backup/status.json` |

## Commands and health (0.21.1-sudo.6+)

```bash
sudo-secretspec backup status
sudo-secretspec backup run
sudo-secretspec doctor
```

`backup status` reads only a bounded, root-owned health summary and returns
nonzero when backup protection needs attention. It does not open the vault or
read keys. `backup run` authenticates through sudo and invokes only the fixed
installed helper/configuration. There are no caller-selected helper, provider,
configuration, or repository flags on the public command. The existing
NOPASSWD broker rules do not authorize backup lifecycle operations.

`doctor` remains read-only. Backup findings are **advisory** and do not disable
credential operations or make an otherwise healthy boundary fail:

| Finding (0.21.1-sudo.6+) | Meaning |
|---|---|
| `BACKUP_NOT_CONFIGURED` | No protected health record exists; setup or the first backup has not completed. |
| `BACKUP_UNHEALTHY` | The health record is invalid/unsafe, capture or replication failed, or no validated snapshot exists. |
| `BACKUP_STALE` | No successful current-vault check within two hours, or timestamps are invalid/future-dated. |
| `BACKUP_REPLICATION_STALE` | The mirror has not recently verified the current local backup commit. |

An old snapshot is healthy when recent checks prove the vault remains unchanged.
A recent failed attempt is not successful protection. Inspect the private
incident log and service health rather than rerunning setup over a missing
vault. Normal backup use requires no plaintext export to the caller.

## Isolated recovery (0.21.1-sudo.6+)

Find the full forty-character commit ID in the encrypted repository's Git log.
Choose an absolute, **new** destination on the same filesystem as backup state:

```bash
# Replace COMMIT with the full lowercase object ID, not a branch or short hash.
sudo-secretspec backup restore COMMIT /var/db/sudo-secretspec-recovery-check
```

The command authenticates, decrypts, verifies checksums, database integrity and
the audit chain, restores original ownership/modes, and refuses existing or live
vault destinations. It never promotes the restored directory into service.
Validate the isolated recovery before an operator restores the live boundary.
Reinstallation and boundary rollback snapshots cannot recover deleted secrets.

If the local history has been lost, recover the remote bare repository into a
protected local directory and recover its separately stored `age` identity.
An authenticated operator can use the installed helper's `restore` command with
`--repo /absolute/path/to/recovered.git` for an isolated recovery; the public CLI
intentionally does not expose repository overrides. Keep the recovered key out
of source control and remove temporary plaintext staging after verification.

Exercise recovery from both copies and from older commits periodically. A
successful Git push alone does not prove decryption or restoration works.

## Deletion attribution and limits (0.21.1-sudo.6+)

Optional macOS Endpoint Security observation records vault-related deletion and
rename events, including the process executable, PID and UID, but never process
arguments, environments or secret contents. It requires root and Full Disk
Access. Enable continuous observation only after its ten-minute benchmark meets
the configured CPU and memory limits. Missing permissions, unsupported schemas,
event loss, and observer failure must be reported; this instrumentation is
independent of backup capture and does not promise retroactive attribution.

Filesystem event delivery and debouncing cannot preserve every intermediate
state of a rapidly changing file. Hourly reconciliation covers missed events;
offline/asleep machines cannot capture or replicate until they resume. The
current external capture protocol detects concurrent changes but is not a
global transaction lock against arbitrary root writes or filesystem damage.
An actor able to delete both repositories and their keys can defeat this
protection; indefinite retention is a policy, not unlimited physical storage.
