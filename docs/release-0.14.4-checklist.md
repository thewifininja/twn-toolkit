# v0.14.4 release checklist

## iPerf3 client diagnostics

- [x] Client mode requires explicit authorization and uses only an already
  installed system `iperf3` binary without installing packages or invoking a
  shell.
- [x] TCP and UDP tests support forward or reverse direction, IPv4 or IPv6,
  optional source binding, bounded parallel streams, and an explicit UDP rate.
- [x] Client runs are capped at 60 seconds and 20 streams and present normalized
  endpoints, transfer, throughput, retransmit or loss/jitter, interval, CPU,
  command, and bounded raw-JSON detail.

## Supervised background listener

- [x] Server mode provides explicit On/Off behavior and accepts multiple
  sequential clients independently of page navigation.
- [x] Enabled listeners resume across toolkit restarts and appear in the
  owner’s dashboard, Live tools tray, system diagnostics, `./twn status`, and
  managed logs.
- [x] The supervisor detects a failed worker, verifies exact recorded
  instance/session/bind/port command lines, removes any orphaned native process,
  and restores the enabled listener without leaving a port conflict.
- [x] Busy bind addresses or ports are rejected before worker launch, listener
  ports remain limited to 1024–65535, only one listener is allowed per user,
  and each accepted server test is capped at ten minutes.
- [x] The newest 50 completed tests are retained privately per user as collapsed
  source-address cards with expandable normalized metrics, intervals, CPU use,
  and bounded full JSON.
- [x] Off, On, sequential forward/reverse results, dashboard and Live tools
  presence, restart recovery, forced-worker-crash recovery, Stop cleanup, light
  and dark themes, and browser console output were exercised locally.

## Compatibility and release gates

- [x] v0.14.4 adds an owner-only `iperf_servers.sqlite3` database on first use
  without changing existing application databases, dependencies, profiles,
  configuration, command-line syntax, or automation data and supports direct
  upgrade from v0.14.3.
- [x] iPerf3 feature PR #80 passed complete feature-branch CI before being
  squash-merged into `main`.
- [x] `APP_VERSION`, README, Quick Start, built-in Help, structured release
  notes, tests, and continuity guidance describe the v0.14.4 behavior.
- [x] Build the v0.14.4 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.14.4` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.14.4.zip` and
  `twn-toolkit-v0.14.4.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
