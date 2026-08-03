# v0.16.5 release checklist

## Bounded observational diagnostics

- [x] System Diagnostics reads iPerf3 listener state without schema setup,
  listener reconciliation, or any other runtime mutation.
- [x] Automation migrations, retention counts, history statistics, and orphan
  artifact evidence use one short read-only connection instead of repeated
  schema-initializing store connections.
- [x] Web diagnostics place short deadlines on SQLite, audit, systemd, and
  launchd status checks while leaving ordinary CLI service status behavior
  unchanged.
- [x] A failed or busy live check produces a visible partial-diagnostics warning
  while the remaining sections still render.
- [x] Per-section and total request durations are available through the standard
  `Server-Timing` response header.

## Responsive diagnostics layout

- [x] Long service-definition paths and other unbroken status values wrap inside
  their cards without creating card or document overflow.
- [x] Shared status grids move from four columns to two before the cards become
  cramped and retain the existing single-column phone layout.
- [x] Services without heartbeat data no longer render an empty
  `heartbeat s ago` label.
- [x] Browser validation at 1600×900 and 1000×900 found no card or document
  overflow; the isolated local Diagnostics request completed in about 36 ms.

## Compatibility and release gates

- [x] Feature PR #102 passed complete Ubuntu and macOS CI before squash merge,
  and its merged-main CI passed before this release branch was created.
- [x] v0.16.5 introduces no Python dependency, database migration,
  profile-format, server-setting, capability, BPF-policy, permission-policy,
  service-lifecycle, or command-line incompatibility.
- [x] Existing automation definitions and history, audit records, service
  ownership, managed listeners, operational limits, instance data, and matched
  recovery guarantees remain unchanged.
- [x] `APP_VERSION`, README, built-in Help, structured release notes, tests,
  autostart documentation, and continuity guidance agree on v0.16.5 behavior.
- [x] Build the v0.16.5 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete pytest suite and release-specific metadata tests: 600
  passed, 6 skipped, and 213 subtests passed locally; the focused release
  metadata and bundle suite passed 36 tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.5` tag only after project-owner
  approval of release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.5.zip` and
  `twn-toolkit-v0.16.5.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. Release publication follows
the squash-merged release PR and successful merged-main CI.
