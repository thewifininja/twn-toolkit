# v0.16.1 release checklist

## Startup-triggered automations

- [x] Automations can run once per host boot or after every complete stopped-to-
  running toolkit start; arming records the current generation as a baseline
  rather than sending an immediate notification.
- [x] Startup-event state and the corresponding durable execution job are
  committed atomically, so scheduler crashes, restarts, and overlapping
  scheduler processes cannot send the same startup event twice.
- [x] Host-boot mode ignores ordinary toolkit, scheduler, and worker restarts;
  toolkit-start mode advances only after a complete stopped-to-running launch.
- [x] Startup dispatch waits up to 120 seconds for a usable non-loopback address
  and still runs after the bound when networking remains unavailable.
- [x] Test now queues a startup-shaped action job without advancing the armed
  baseline, and startup cards expose the selected scope, latest event, network
  wait, and retained startup/action history.

## System identity and notification templates

- [x] One bounded identity collector owns the configured instance name,
  hostname, toolkit version, current IPv4/IPv6 addresses, and reachable toolkit
  URLs without reading or exposing credentials.
- [x] Webhook/API, Email, and Syslog templates share explicit `toolkit.*` and
  `startup.*` variables; exact JSON list tokens remain typed arrays while text
  and embedded JSON use compact list text.
- [x] Internal boot/toolkit generation identifiers are excluded from action
  evidence and retained results.
- [x] The launcher records a toolkit-start generation only after the web service
  becomes ready and before the scheduler starts; redundant starts and
  scheduler-only restarts do not rewrite it.

## Compatibility, documentation, and release gates

- [x] Toolkit migration 3 snapshots the automation database before automation
  schema migration 7 adds durable startup-event state; existing definitions,
  pipelines, history, and retained output remain compatible.
- [x] v0.16.1 introduces no Python dependency, profile-format, server-setting,
  or command-line incompatibility and supports direct upgrade from v0.16.0.
  Older code must not be run directly against the migrated automation database;
  use the matched upgrade rollback/recovery snapshot instead.
- [x] Feature PR #93 passed complete platform CI before squash merge, and merged
  `main` CI run 30759982442 passed before release preparation.
- [x] `APP_VERSION`, README, Quick Start, built-in Help, structured release
  notes, Automation documentation, tests, and continuity guidance describe the
  v0.16.1 behavior.
- [x] Build the v0.16.1 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.1` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.1.zip` and
  `twn-toolkit-v0.16.1.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
