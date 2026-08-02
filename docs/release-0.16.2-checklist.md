# v0.16.2 release checklist

## Boot-service upgrade lifecycle

- [x] Installer-driven starts identify application-code replacement separately
  from an ordinary `./twn restart`, which retains its lightweight managed
  pause/resume behavior.
- [x] A running systemd or launchd launcher is retired deliberately after the
  installer refreshes application code and dependencies, allowing the OS
  manager to load the new `twn` script from disk.
- [x] Upgrade completion waits for a different launcher PID, the web process,
  automation scheduler, worker supervisor, and saved endpoint metadata.
- [x] The reload retains the installed normal service account and existing
  Linux capability or macOS BPF policy without another administrator prompt or
  a separate `./twn service restart`.
- [x] Manual installations continue to start normally, and the installer does
  not silently install, remove, or alter an optional OS service definition.

## Failure handling and compatibility

- [x] Launcher replacement is bounded to three minutes and timeout output points
  operators to `./twn service status` and `./twn service logs`.
- [x] v0.16.2 introduces no Python dependency, database migration,
  profile-format, server-setting, permission-policy, or command-line
  incompatibility and supports direct upgrade from v0.16.1.
- [x] Existing startup automations, managed listeners, service ownership,
  optional network capabilities, instance data, and matched recovery points are
  preserved.
- [x] Installer tests assert that only installer-driven start/restart commands
  request a launcher reload; launcher tests assert PID replacement and complete
  managed-process readiness.

## Documentation and release gates

- [x] Feature PR #95 passed complete platform CI before squash merge.
- [x] Merged `main` CI run 30761508352 passes before release preparation is
  committed.
- [x] `APP_VERSION`, README, Quick Start, built-in Help, structured release
  notes, service and upgrade documentation, tests, and continuity guidance
  describe the v0.16.2 behavior.
- [x] Build the v0.16.2 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.2` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.2.zip` and
  `twn-toolkit-v0.16.2.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
