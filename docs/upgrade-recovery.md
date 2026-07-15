# Upgrade and Recovery

Use this procedure for every release upgrade. The toolkit preserves instance
data during installation and snapshots affected SQLite databases before
numbered migrations, but a full instance backup is the recovery boundary for
profiles, credentials, certificates, settings, databases, and migration
snapshots together.

## Before upgrading

1. Confirm the current service state and record the installed version shown in
   the app footer or Help page.
2. Stop the toolkit with `./twn stop`.
3. Copy the entire ignored `instance/` directory to protected storage. Preserve
   permissions and restrict access because the backup can contain API tokens,
   saved credentials, private keys, and user records.
4. Keep the previous release tag available locally so application code and
   instance data can be restored as a matched pair.

Do not copy a live SQLite database as the release backup. Stop the toolkit
first, or use a SQLite-aware backup tool.

## Upgrade

1. Switch to the intended release tag or update the release checkout.
2. Run `./install.sh` as the normal toolkit owner, without `sudo`.
3. Run `./twn status` and confirm that the web service, automation scheduler,
   worker supervisor, and every enabled transfer service are running.
4. Open a printed toolkit URL, sign in, and confirm the installed version on
   the Help page.
5. Verify one important saved profile and any enabled automation or local
   transfer service before returning the installation to normal use.

Rerunning the installer on an active installation now restarts all managed
processes. Installation is not complete until that restart succeeds.

## Roll back

If startup, migration, authentication, or saved-state verification fails:

1. Stop the toolkit with `./twn stop`. If normal stop fails, inspect
   `./twn status` and `./twn logs` before terminating any process manually.
2. Preserve the failed `instance/` directory separately for diagnosis.
3. Restore the complete pre-upgrade `instance/` backup with its original owner
   and restrictive permissions.
4. Switch the application checkout back to the recorded previous release tag.
5. Run `./install.sh`, then repeat the status, sign-in, version, profile, and
   enabled-service checks above.

Do not combine older application code with the post-migration instance unless
that exact downgrade path has been tested. Database migration snapshots under
`instance/migration_backups/` are useful for diagnosis and targeted recovery;
the full stopped-instance backup remains the supported rollback unit.

## Recovery evidence

When reporting an upgrade problem, retain the release tags involved, the
installer output, `./twn status`, relevant output from `./twn logs`, and a copy
of the failed instance. Remove secrets before sharing logs or data outside the
trusted operations team.
