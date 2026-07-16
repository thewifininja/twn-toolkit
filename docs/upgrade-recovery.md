# Upgrade and Recovery

The supported upgrade path is **Administration → Updates & Recovery** or the
matching `./twn upgrade` command. Neither path requires Git, the GitHub CLI, or
manual tag selection. Both use the same request-independent upgrade engine.

Installations running v0.10.2 or older need one final conventional upgrade to
v0.11.0, the first updater-enabled release. After that transition, use the app
or CLI workflow below. The updater cannot retroactively create the pre-upgrade
instance backup that an older installation did not make.

## What a supported release contains

Every published stable release intended for in-app upgrade has two assets:

- `twn-toolkit-vX.Y.Z.zip`, containing application files and an internal
  manifest with a SHA-256 digest, size, and mode for every file.
- `twn-toolkit-vX.Y.Z.zip.sha256`, containing the digest for the whole bundle.

The release workflow builds these assets from the published tag and attaches
them to the release. The updater accepts only stable versions newer than the
installed version, verifies both integrity layers, rejects unsafe archive
entries, and enforces file-count and size limits.

## Upgrade from the app

1. Sign in as a system administrator and open **Updates & Recovery**.
2. Select **Check for updates**. This contacts the official public release API;
   it does not require a GitHub account or locally installed GitHub software.
3. Review the version and release notes, confirm the restart, and choose
   **Download and upgrade**.
4. Keep the progress page open. It tolerates the expected period when the web
   service is unavailable and reconnects after restart.
5. Review the terminal result and recovery-point identifier after the toolkit
   returns.

The **Manual release bundle** form accepts the same official ZIP when the host
cannot access the release API. If a release changes Python dependencies, the
host must still have package-index access or the required packages in its pip
cache.

## Upgrade and recovery commands

```bash
./twn upgrade
./twn upgrade --version 0.11.0
./twn upgrade --bundle /path/to/twn-toolkit-v0.11.0.zip
./twn backup
./twn upgrade-status
./twn rollback RECOVERY_POINT_ID
```

Interactive confirmation is required. Automation may use `--yes` only after it
has independently reviewed the version and maintenance window.

## Automatic recovery boundary

Before changing application files, the updater stops every managed service,
checks free space, copies the complete stopped `instance/`, copies the matching
managed application code, and writes an integrity manifest for the pair.

Recovery points live under owner-only `.twn-upgrades/backups/` outside
`instance/`, avoiding recursive backups. The five newest valid points are
retained. They contain credentials, private keys, operational files, databases,
and application code and must be protected like the live instance.

After installation the updater verifies the reported version, managed process
health, enabled-service state, and every SQLite database. A failure automatically
stops the partial installation, verifies the recovery point, restores both code
and instance data, restarts, and validates the restored version. The terminal
result is written to the administrative audit trail.

The launcher enforces one automation scheduler, worker supervisor, and transfer
daemon of each type per installation root. It also cleans exact-instance legacy
duplicates during start and stop. This prevents duplicate automation execution
and prevents an orphaned supervisor or transfer daemon from relaunching a stopped
installation's service and occupying the clone or replacement service's port.

Installer output is sent directly to the null device instead of retained in an
updater pipe. Besides avoiding exposure of package-repository credentials, this
prevents daemon helper processes from inheriting a captured pipe and holding the
upgrade operation open after startup has completed.

Managed daemons defer importing libraries that create process helpers or event
loop descriptors until after daemonization. This makes the protection effective
while upgrading from an older toolkit whose updater still uses captured installer
pipes without risking library-owned descriptors such as macOS kqueues.

## Rollback rule

Rollback is a **matched restore**, not a database downgrade. The toolkit never
runs older code against newer instance data. Choose a recovery point from the UI
or pass its identifier to `./twn rollback`; both code and complete instance data
are restored together.

An installation upgraded before this feature cannot recreate a missing old
instance backup. A current baseline recovery point protects future changes but
does not enable return to an earlier state that was never captured.

## Manual emergency recovery

If neither the restored web service nor CLI can complete, preserve the live
installation and `.twn-upgrades/`, inspect `.twn-upgrades/upgrade.log` and
`status.json`, and do not mix files from different recovery points. Restore the
`code/` and `instance/` pair from one verified recovery point as the toolkit
owner, then run its `install.sh`.

Retain the operation and recovery-point identifiers and relevant log excerpt
when reporting failure. Remove secrets before sharing logs or instance data.
