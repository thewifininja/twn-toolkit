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

Before changing application files, the updater stops every managed service and
checks free space. It copies non-database `instance/` data, creates each
top-level SQLite database through SQLite's online backup API, consolidates WAL
state into the snapshot, and runs `PRAGMA quick_check` against both the live
source and completed copy. It then copies the matching managed application code
and writes an integrity manifest for the pair. A malformed source or snapshot
aborts before application files change and restarts the untouched installation.

Recovery points live under owner-only `.twn-upgrades/backups/` outside
`instance/`, avoiding recursive backups. The five newest valid points are
retained. They contain credentials, private keys, operational files, databases,
and application code and must be protected like the live instance.

After installation the updater verifies the reported version, managed process
health, enabled-service state, and every SQLite database. A failure automatically
stops the partial installation, verifies both the recovery-point manifest and
its SQLite databases, restores code and instance data, restarts, and validates
the restored version. The terminal result is written to the administrative
audit trail.

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

## Installations managed at boot

An installed systemd unit or macOS LaunchDaemon set remains outside the release
bundle. Upgrade, rollback, and recovery detect the loaded OS supervisor and
pause the managed toolkit through it. After application code is replaced, the
installer starts a validation-only process set while keeping the original
launcher paused. The updater validates the installed version, complete managed
process set, enabled listeners, and databases, then records its terminal result,
cleans the staged request and bundle, and removes the operation lock last.

Only after that durable finalization signal does a deferred handoff stop the
temporary process set and let systemd or launchd load the new `twn` from disk
with the same normal service account and security context. This prevents the OS
service manager from terminating the detached updater as part of an early
cgroup or job reload. The temporary validation start suppresses the startup
automation event; the final OS-managed start records it exactly once. Automatic
rollback instead lets the original in-memory launcher adopt the validated
restored process set when its version matches. Handoff details are available in
`.twn-upgrades/service-reload.log`.

No recurring `./twn service restart` or administrator prompt is required. The
v0.17.0 transition is a one-time exception: an existing macOS host must run
`sudo ./twn service install` after its code upgrade so the direct web and worker
property lists plus the protected TCP connector can be installed beneath
`/Library/LaunchDaemons` and `/Library/PrivilegedHelperTools`. The connector is
the only root process; it accepts only the configured service UID and passes
connected descriptors without application credentials or payload data. Later
upgrades retain that layout. The operation does not silently install, remove,
or change the optional Linux network-capability policy. An ordinary
`./install.sh` run outside an active upgrade continues to reload a boot-managed
launcher synchronously.

After an upgrade on a boot-managed host, verify both layers:

```bash
./twn service status
./twn status
```

Do not move a service-managed checkout as part of an upgrade. The OS definition
stores an absolute path, and `.venv` also contains absolute paths. Use the
documented uninstall, relocate/fresh-clone, reinstall, and service-install flow
in [Autostart Service](autostart-service.md).

## Rollback rule

Rollback is a **matched restore**, not a database downgrade. The toolkit never
runs older code against newer instance data. Choose a recovery point from the UI
or pass its identifier to `./twn rollback`; both code and complete instance data
are restored together.

An installation upgraded before this feature cannot recreate a missing old
instance backup. A current baseline recovery point protects future changes but
does not enable return to an earlier state that was never captured.

The v0.17.0 macOS service layout is external to a recovery point. Do not restore
v0.16.7 or older code while its additional LaunchDaemons and connector remain
loaded. If that downgrade is ever required, use the still-current v0.17.0 code
to run `sudo ./twn service uninstall`, perform the matched code-and-instance
rollback, and then run the restored version's `sudo ./twn service install`.
This removes all v0.17.0 property lists, the helper executable, Unix socket, and
activation markers before older code takes control. It retains the instance,
service logs, and recovery points.

## Manual emergency recovery

If neither the restored web service nor CLI can complete, preserve the live
installation and `.twn-upgrades/`, inspect `.twn-upgrades/upgrade.log` and
`status.json`, and do not mix files from different recovery points. Restore the
`code/` and `instance/` pair from one verified recovery point as the toolkit
owner, then run its `install.sh`.

Retain the operation and recovery-point identifiers and relevant log excerpt
when reporting failure. Remove secrets before sharing logs or instance data.
