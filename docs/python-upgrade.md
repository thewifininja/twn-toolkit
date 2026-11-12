# Moving to Python 3.11 or newer

The toolkit requires Python 3.11+. Python 3.12+ is recommended. Existing users
can use the release migration tool instead of manually updating source or
renaming virtual environments. Installing Python 3.11+ alongside the existing
interpreter is the only OS prerequisite; the tool never replaces system Python,
runs sudo, or removes the old interpreter.

## Automated migration

Use a maintenance window and finish all jobs and terminal sessions on this host.
Download `twn-runtime-migrate.pyz` and its `.sha256` from the reviewed stable
release's official GitHub assets. Verify the tool checksum before executing it:

```bash
sha256sum -c twn-runtime-migrate.pyz.sha256
# macOS: shasum -a 256 -c twn-runtime-migrate.pyz.sha256
```

Run it as the account that owns the toolkit, without sudo. Substitute the exact
reviewed release version and installation path:

```bash
python3 twn-runtime-migrate.pyz --root /path/to/twn-toolkit --version X.Y.Z
```

The bootstrap works on Python 3.10 and discovers an installed Python 3.11+.
Select one explicitly with `--python /absolute/path/to/python3.12`. After reviewing
the maintenance window, unattended execution may add `--yes`. No migration
release/tag has been published by this change; `X.Y.Z` is a placeholder, not a
command to run against a development branch.

The tool:

1. Checks ownership, idle jobs/terminals, the selected interpreter, free space,
   and the upgrade/setup locks. It refuses to steal an active operation's lock.
2. Downloads the exact stable release's official bundle and checksum, verifies
   the archive and all file hashes, and checks version/runtime compatibility.
   Offline use accepts `--bundle /path/release.zip --sha256 PUBLISHED_DIGEST`.
3. Creates a private environment at its permanent path under
   `.twn-upgrades/runtime-migrations/`, installs the hash-locked dependencies,
   runs `pip check`, and checks source compilation. The old environment and
   running services are untouched if this preparation fails.
4. Runs a preserved copy of the migration worker with that staged interpreter,
   confirms idle work again, stops the toolkit, and creates a verified code/data
   recovery point. It records an integrity-checked reference to the old runtime.
5. Preserves the old `.venv`, switches `.venv` to the staged environment,
   applies the verified application bundle, and checks version, process health,
   enabled services, and SQLite integrity. Environment launch scripts keep their
   correct absolute paths because the staged environment is never renamed.
6. On a validation failure, restores matching code, instance data and the old
   environment, then checks the restored installation. The old runtime remains
   available for later rollback through **Updates & Recovery** as well.

The account's keys, identities and instance stay with this installation. Migrate
each Mainframe/Agent host separately; do not copy one host's instance to another.
Existing format-1 updaters still reject format-2 bundles. The independently
packaged migration tool is the automated transition around that limitation;
afterward, normal app/CLI upgrades resume. No bridge release or manual source
checkout is required.

## Interrupted migration

A private journal and a preserved `migrate.pyz` are retained under
`.twn-upgrades/runtime-migrations/IDENTIFIER/`. If power loss or termination
interrupts migration, run the verified release tool again with the journal path:

```bash
python3 twn-runtime-migrate.pyz --recover /path/to/twn-toolkit/.twn-upgrades/runtime-migrations/IDENTIFIER
```

Recovery refuses a still-running worker. Before cutover it cancels incomplete
preparation without touching the installed toolkit; after cutover it restores
the recovery point and original runtime rather than continuing a partial update.
It also works if `.venv` is temporarily missing. If automatic recovery cannot
finish, the operation lock and all recovery files remain in place for diagnosis.
Do not manually rename/delete environments or remove that lock to force another
upgrade. `plan.json` records the phase and the matching backup identifier.

Keep the old Python interpreter installed and retain migration journals and
recovery points until acceptance and the rollback retention window are complete.
They contain private code/data/runtime recovery material and must remain owned
by the toolkit account. Runtime preservation is additional to ordinary code/data
recovery points; earlier recovery points without runtime metadata retain their
historical behavior. A pre-existing `.venv` symlink requires operator review instead of another
automatic migration. Already-migrated installations use the normal updater and
recovery commands.

## Fresh installation

`install.sh` uses an existing compatible `.venv/bin/python`, otherwise `python3`.
Select another installed interpreter with:

```bash
TWN_TOOLKIT_PYTHON=/absolute/path/to/python3.12 ./install.sh --non-interactive
```

The same selection works with guided setup. The installer continues to reject an
unsupported existing environment without changing it; use the release migration
tool for an existing installation. This keeps a normal installation command
from unexpectedly performing a runtime cutover.
