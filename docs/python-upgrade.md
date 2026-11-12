# Moving to Python 3.11 or newer

The toolkit requires Python 3.11+. Python 3.12+ is recommended. Install the new
interpreter alongside the operating system's Python; do not replace the system
`python3` executable or remove the interpreter used by the old virtual environment.

## Fresh installation and interpreter selection

The installer reuses an existing `.venv/bin/python` by default, or uses
`python3` when no environment exists. Select a different installed interpreter
with an absolute executable path:

```bash
TWN_TOOLKIT_PYTHON=/absolute/path/to/python3.12 ./install.sh --non-interactive
```

The same variable works with `./install.sh --guided` and `./twn setup`.
The installer checks both that interpreter and an existing `.venv/bin/python`
before creating an environment, installing packages, or starting/stopping services.
An old virtual environment is rejected and preserved, even if the selected
bootstrap interpreter is supported. A system Python upgrade alone does not
upgrade a virtual environment.

## Existing installation: one-time migration

Plan a maintenance window with no active device operations. Mainframe and Agent
hosts each need their own runtime migration; preserve their separate instance
keys and identities. Do not copy one host's instance onto another.

1. While the old installation still works, create and verify a recovery point
   with `./twn backup --yes`. Record its identifier and check `./twn upgrade-status`.
2. Stop the autostart service with `./twn service stop` if installed, then run
   `./twn stop`. Confirm the service is paused/stopped and no toolkit worker is
   running. Keep it stopped while copying or replacing files.
3. Make a separate, owner-only backup of the entire stopped installation,
   including `instance/`, `.venv/`, `.twn-upgrades/`, hidden files and local changes.
   Verify the copy includes the instance encryption key and databases. This full
   copy is needed because an updater recovery point does not include `.venv`.
4. Install Python 3.11+ side by side and verify its executable with
   `/absolute/path/to/python3.12 --version`. Do not uninstall Python 3.10 yet.
5. Update application code to the reviewed release that introduces this minimum.
   Existing format-1 updaters cannot perform this transition: format-2 bundles
   are intentionally rejected before installation. For a Git checkout, preserve
   local edits, require a clean working tree, fetch tags, and check out the exact
   reviewed release tag. Do not switch to a moving development branch. For an
   archive installation, use the reviewed release source and preserve instance
   data, recovery points and the saved environment; do not extract the upgrade
   bundle's manifest as application source or overwrite runtime data.
6. Rename `.venv` to `.venv-python310-saved` in the stopped installation. Do not
   delete it. This frees the original `.venv` path for the supported interpreter;
   virtual environments must be created at their final path, not built elsewhere
   and moved (their launch scripts contain absolute paths).
7. Run the installer with the supported interpreter using the command above.
   It creates `.venv`, verifies locks, installs hash-pinned dependencies, runs
   `pip check`, and starts the toolkit. Review the result and `./twn status`.
8. Confirm administrator access, saved hosts/credentials, enabled services and
   Mainframe/Agent connectivity. Resume the autostart service if it remains
   paused. Retain the complete pre-migration backup and old interpreter until
   acceptance is complete. Normal app/CLI upgrades work again with format 2.

If the old installation already uses Python 3.11+, retain its compatible `.venv`;
step 6 is unnecessary. Older format-1 updater code still needs the one-time source
transition, even on a compatible interpreter. No new release tag is created by
this policy change; the release owner must document the actual target tag.

## If migration fails

Keep the toolkit and autostart service stopped. Preserve the failed installation
for diagnostics. Restore the complete pre-migration code, instance and original
virtual environment together at the original absolute installation path, then
start the restored service and verify it. Do not combine an old environment with
new code, restore only the database, or point the old service at the new checkout.
The preserved Python 3.10 interpreter is required to run the restored environment.
An automatic updater rollback is not a substitute for this full runtime backup.

## Upgrade bundle compatibility

Format 2 declares `minimum_python: "3.11"`; new validators check it before
scheduling an upgrade and again before applying its files. Legacy format-1
validators reject format 2 before launching an upgrade. This deliberately blocks
an unsafe automatic transition instead of replacing source and discovering an
unsupported runtime during package installation. The new validator continues
accepting format-1 bundles under the existing integrity and version checks.
