# v0.16.7 release checklist

## Toolkit timezone

- [x] System Settings shows the current toolkit time, resolved IANA timezone,
  UTC offset, and whether the value follows the host or an explicit override.
- [x] Blank settings follow the host timezone; explicit settings validate IANA
  names, handle daylight-saving transitions, persist atomically with owner-only
  permissions, and produce an audit event.
- [x] Saving applies immediately without restarting the toolkit or changing the
  operating-system clock.
- [x] New calendar schedules begin with the resolved toolkit timezone while
  every saved schedule retains its own explicit timezone.

## Localized automation notifications

- [x] Webhook/API, Email, and Syslog actions share explicit localized ISO,
  human-readable display, UTC, resolved-timezone, and startup-time variables.
- [x] Existing `{{timestamp}}` and `{{startup.occurred_at}}` variables remain
  UTC, and existing saved templates are never rewritten during upgrade.
- [x] Newly created webhook payloads default to localized ISO time plus the
  resolved timezone; newly created email messages default to display time.
- [x] System identity, editor guidance, built-in Help, README, Quick Start,
  automation documentation, and continuity guidance describe the same contract.

## Compatibility and release gates

- [x] Feature PR #106 passed complete Ubuntu and macOS CI before squash merge,
  and its merged-main CI passed before this release branch was created.
- [x] v0.16.7 introduces no Python dependency, database migration,
  profile-format change, service-lifecycle change, permission change,
  command-line incompatibility, or operating-system configuration change.
- [x] Host fallback, explicit settings, malformed data, DST offsets,
  administration, audit policy, schedule defaults, startup identity, and
  rendered action variables have dedicated regression coverage.
- [x] `APP_VERSION`, README, built-in Help, structured release notes, tests,
  and continuity guidance agree on v0.16.7 behavior.
- [x] Build the v0.16.7 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete pytest suite and focused release metadata tests: 609
  passed, 6 skipped, and 214 subtests passed locally; the focused release
  metadata and upgrade-manager suite passed 36 tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.7` tag only after project-owner
  approval of release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.7.zip` and
  `twn-toolkit-v0.16.7.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. Release publication follows
the squash-merged release PR and successful merged-main CI.
