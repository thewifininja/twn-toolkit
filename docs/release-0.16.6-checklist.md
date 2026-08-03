# v0.16.6 release checklist

## Production-scale diagnostics performance

- [x] Live production `Server-Timing` evidence isolated an approximately
  10.38-second Diagnostics request to about 8.94 seconds of SQLite integrity
  work and 1.21 seconds of automation storage work.
- [x] SQLite files larger than 64 MiB are labeled for an intentional manual
  maintenance-window integrity check without being scanned during page load.
- [x] Smaller live integrity checks retain both a SQLite progress deadline and
  thread-safe interrupt watchdog, with an explicit bounded status on timeout.
- [x] Automation retention summaries use the existing compact history index
  instead of scanning large evidence payloads.

## Automation workspace read path

- [x] Definitions, automation cards, recent checks and runs, and job counters
  are collected through one consistent read-only SQLite connection.
- [x] Workspace rendering no longer initializes schema or checks reusable and
  numbered migrations separately for every card and library lookup.
- [x] Automation responses publish workspace, context, render, and total
  durations through the standard `Server-Timing` header.
- [x] A production-shaped 446.7 MiB database with 100,000 retained checks
  completed the workspace snapshot in about 0.7 ms, the automation diagnostics
  snapshot in about 7.4 ms, and the large-file live-check decision in 0.2 ms.

## Compatibility and release gates

- [x] Feature PR #104 passed complete Ubuntu and macOS CI before squash merge,
  and its merged-main CI passed before this release branch was created.
- [x] v0.16.6 introduces no Python dependency, database migration, stored-data
  change, profile-format change, service-lifecycle change, permission change,
  or command-line incompatibility.
- [x] Existing automation definitions and history, retention behavior, service
  ownership, managed listeners, instance data, audit records, and recovery
  guarantees remain unchanged.
- [x] `APP_VERSION`, README, built-in Help, structured release notes, tests,
  and continuity guidance agree on v0.16.6 behavior.
- [x] Build the v0.16.6 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete pytest suite and focused release metadata tests: 604
  passed, 6 skipped, and 213 subtests passed locally; the focused release
  metadata and upgrade-manager suite passed 36 tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.6` tag only after project-owner
  approval of release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.6.zip` and
  `twn-toolkit-v0.16.6.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. Release publication follows
the squash-merged release PR and successful merged-main CI.
