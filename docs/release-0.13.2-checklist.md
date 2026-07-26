# v0.13.2 release checklist

## Recovery behavior

- [x] `./twn recover` loads the configured or last-running endpoint, stops the
  tracked service set, removes orphaned toolkit Gunicorn processes, confirms the
  port is available, and returns the toolkit to a running state.
- [x] A valid running installation can use recovery as a guarded restart, while
  a missing or stale PID file does not prevent recovery of the matching server.
- [x] Linux listener discovery uses `ss`, `lsof`, or `fuser` when available and
  falls back to `/proc` TCP socket ownership; macOS uses `lsof`.
- [x] Process matching requires the Gunicorn application marker plus this
  installation's executable path or working directory.

## Privilege and process safety

- [x] Recovery requests sudo only when a root-owned process, hidden listener, or
  root-owned instance file requires elevated access.
- [x] Elevated recovery stops the verified process, repairs `instance/`
  ownership, drops back to the invoking user, and starts the toolkit normally.
- [x] A PID file is trusted only when its PID matches a verified toolkit server,
  preventing a recycled stale PID from reaching the existing stop path.
- [x] A process occupying the configured port is never terminated unless it is
  verified as this installation's Gunicorn server; unrelated listeners produce
  a diagnostic and leave their process untouched.

## Product and compatibility

- [x] v0.13.2 introduces no application-database, profile, configuration, or
  dependency migration.
- [x] CLI usage, README, Quick Start, built-in Help, structured release notes,
  continuity guidance, and tests describe the recovery workflow and its safety
  boundaries.
- [x] Automated tests cover Linux and macOS listener selection, Linux `/proc`
  parsing, installation-scoped process matching, unrelated-listener rejection,
  changed Gunicorn process titles, and bounded termination.

## Release candidate gates

- [x] Build the v0.13.2 bundle from the release-preparation source and verify
  its internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass pull-request CI on Ubuntu 3.10, Ubuntu 3.13, macOS 3.13, repository
  checks, and the dependency audit.
- [ ] On Ubuntu, reproduce a privileged start followed by an unprivileged
  restart; run `./twn recover` and verify ownership repair, port release, and
  normal-user web/scheduler/supervisor health.
- [ ] Confirm an unrelated TCP listener on the configured port is reported and
  left running.
- [ ] After approval and squash merge, pass merged-main CI before creating the
  tag.
- [ ] Create and push the exact annotated `v0.13.2` tag only after every
  preceding gate is complete and the project owner explicitly approves it.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the release contains `twn-toolkit-v0.13.2.zip` and
  `twn-toolkit-v0.13.2.zip.sha256` before testing production discovery.
- [ ] From a production v0.13.1 installation, discover and install v0.13.2;
  verify recovery-point creation, web/scheduler/supervisor health, enabled
  services, certificate request history, audit history, and upgrade status
  after restart.
- [ ] Exercise rollback to the matched v0.13.1 recovery point and confirm the
  prior code and instance data return healthy.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
