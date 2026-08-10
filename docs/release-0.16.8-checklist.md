# v0.16.8 release checklist

## macOS service networking

- [x] Gunicorn, automation, supervisor, and enabled transfer workers remain
  foreground children of the persistent launcher in macOS LaunchDaemon mode.
- [x] Manual launches and Linux service mode retain their existing daemon path.
- [x] Foreground automation and supervisor workers write and clean their PID
  files, and shutdown retains the web PID while stopping sibling workers.
- [x] Nested Paramiko errno 65 failures on macOS provide Local Network Privacy
  and toolkit TCP Port Scanner guidance without misdiagnosing other platforms.

## Scheduled packet capture

- [x] Automation-triggered PCAP invokes `packet_capture_exec.py` by absolute
  path and succeeds when launched from outside the checkout directory.
- [x] SSH, remote transfer, syslog, webhook, email, and condition evaluators do
  not depend on the automation worker's current directory.
- [x] Standalone PCAP, managed iPerf, and upgrade module launches retain an
  explicit checkout `cwd`, with regression assertions for that invariant.
- [x] The production incident, operational mitigation, interface observation,
  administrator fallback constraints, and support procedure are documented.

## Compatibility and release gates

- [x] v0.16.8 introduces no Python dependency, database migration, stored-data
  change, profile-format change, server-setting change, operating-system
  configuration change, or command-line incompatibility.
- [x] Service ownership, automation definitions and history, captures, managed
  listeners, instance data, audit records, and matched rollback are preserved.
- [x] `APP_VERSION`, README, built-in Help, structured release notes, tests,
  autostart guidance, incident notes, and continuity guidance agree on v0.16.8.
- [x] Build the exact v0.16.8 candidate bundle and verify its 338-file internal
  manifest and external SHA-256 checksum.
- [x] Pass shell syntax and the complete pytest suite: 614 passed, 6 skipped,
  and 214 subtests passed locally. The focused release metadata, upgrade,
  packet-capture, SSH-diagnostic, launcher, and iPerf suite passed 82 tests.
- [ ] Upgrade the production LaunchDaemon installation through the manual bundle
  workflow and retain the matched v0.16.6 recovery point.
- [ ] Validate production service ownership, restart behavior, toolkit TCP/SSH,
  scheduled PCAP, and simultaneous five-switch SSH plus PCAP.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.8` tag only after project-owner
  approval of release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.8.zip` and
  `twn-toolkit-v0.16.8.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this candidate branch. Release publication follows
production validation, review, the squash-merged release PR, and successful
merged-main CI.
