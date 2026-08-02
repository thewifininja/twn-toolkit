# v0.16.3 release checklist

## Service-managed upgrade finalization

- [x] A boot-managed upgrade keeps the original systemd or launchd launcher
  paused while the replacement process set is started and validated.
- [x] Terminal status, administrative audit evidence, staged request and bundle
  cleanup, and the operation lock are finalized before the OS service manager
  reloads the launcher from disk.
- [x] The handoff prevents systemd `KillMode=mixed` or equivalent job cleanup
  from terminating the detached updater before its final writes complete.
- [x] A validation-only start suppresses startup-generation recording so the
  final OS-managed start emits exactly one toolkit-start automation event.
- [x] A bounded handoff timeout restores launcher ownership and retains the
  healthy validated process set; diagnostics live in
  `.twn-upgrades/service-reload.log`.

## Rollback and compatibility

- [x] The current updater prepares the handoff before application replacement
  or restore, and a v0.16.2 compatibility bridge can defer reload when the
  already-installed updater reaches the new target installer.
- [x] Matched instance restores cannot make an older launcher PID discoverable
  during the active transaction, including rollback to older lifecycle code.
- [x] A successful automatic rollback can let the original matching launcher
  adopt the validated restored process set instead of forcing another reload.
- [x] v0.16.3 introduces no Python dependency, database migration,
  profile-format, server-setting, capability, BPF-policy, permission-policy, or
  command-line incompatibility and supports direct upgrade from v0.16.2.
- [x] Ordinary `./twn restart`, manual installer reloads outside an active
  supported upgrade, service ownership, managed listeners, instance data, and
  matched recovery guarantees remain unchanged.

## Documentation and release gates

- [x] Hotfix PR #97 passed complete platform CI before squash merge.
- [x] Merged `main` CI run 30763944991 passed before release preparation began.
- [x] `APP_VERSION`, README, built-in Help structured release notes, tests,
  Quick Start, service and upgrade documentation, and continuity guidance
  describe the v0.16.3 behavior.
- [x] Build the v0.16.3 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.3` tag only after project-owner
  approval of release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.3.zip` and
  `twn-toolkit-v0.16.3.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. Release publication follows
the squash-merged release PR and successful merged-main CI.
