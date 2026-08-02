# v0.15.1 release checklist

## Automation Ping cadence

- [x] Condition deadlines remain anchored to the prior start-to-start cadence
  instead of drifting from evaluation completion time.
- [x] The scheduler does not claim and discard a due condition round while the
  preceding check for that automation is still running, and condition rounds
  for one automation never overlap.
- [x] A late waiting round begins after completion, long pauses resume without
  replaying a backlog, and retained history records the observation-start time.
- [x] Automation Ping accepts 0.1–10 second timeouts when the verified `fping`
  engine is active, including 0.9 seconds, while compatibility mode retains a
  one-second minimum.

## Packet Replay from Datastore

- [x] Packet Replay can preview a recursively listed classic `.pcap` or `.cap`
  file from the contained Datastore while retaining browser upload and raw
  Ethernet hex as mutually exclusive sources.
- [x] Non-administrators need both Packet Replay and Datastore permissions to
  list or select stored captures; contained path resolution, regular-file
  checks, symbolic-link rejection, suffix validation, and the 256 KiB limit
  remain enforced server-side.
- [x] Stored and uploaded multi-packet captures use the same prepared preview,
  confirmation, MAC/VLAN transformation, repeat, 10,000-frame, and five-minute
  scheduled-duration limits without re-reading the source during send.
- [x] PCAPNG remains supported for inspection but is explicitly excluded from
  replay until its capture parser is implemented.

## Compatibility and release gates

- [x] v0.15.1 introduces no application-database schema, dependency, profile,
  configuration, command-line, or automation migration and supports direct
  upgrade from v0.15.0.
- [x] Automation cadence PR #87 and Packet Replay PR #86 passed complete
  feature-branch CI before being squash-merged into `main`; PR #86 was rebased
  onto the merged cadence fix and passed refreshed CI before merge.
- [x] `APP_VERSION`, README, Quick Start, built-in Help, structured release
  notes, focused documentation, tests, and continuity guidance describe the
  v0.15.1 behavior.
- [x] Build the v0.15.1 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.15.1` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.15.1.zip` and
  `twn-toolkit-v0.15.1.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
