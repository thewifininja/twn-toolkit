# v0.14.0 release checklist

## Multi-SSH Commandlets and variables

- [x] Advanced Multi-SSH supports a spreadsheet-style table and Raw Matrix
  input with fixed Name and Host columns plus operator-defined variables.
- [x] Stored Commandlets save reusable commands, metadata, timeouts, and an
  optional target matrix without saving credentials.
- [x] Signed previews bind approval to the rendered per-host plans and are
  invalidated when execution inputs change.
- [x] Basic Multi-SSH remains available as the default straightforward
  host-list workflow.

## Fleet execution and automation

- [x] Interactive and automated SSH diagnostics accept up to 5,000 targets,
  submit batches of 50, and limit active connections to 10.
- [x] Aggregate and per-host output capture remain bounded for large fleets.
- [x] SSH collection automation actions support the shared target matrix,
  per-host variables, direct authoring, and optional Commandlet snapshots.
- [x] Legacy automation host lists remain readable and normalize into the new
  matrix model when saved.

## Compatibility and persistence

- [x] v0.14.0 introduces no application-database schema, dependency,
  command-line, or existing configuration migration.
- [x] The optional owner-only Commandlet profile contains no credentials and is
  included in profile backup and restore.
- [x] README, Quick Start, built-in Help, automation documentation, structured
  release notes, and continuity guidance describe the shipped behavior.
- [x] The feature pull request and its merged-main CI passed on Ubuntu Python
  3.10, Ubuntu Python 3.13, macOS Python 3.13, repository checks, and the
  dependency audit.

## Release gates

- [x] Build the v0.14.0 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.14.0` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.14.0.zip` and
  `twn-toolkit-v0.14.0.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
