# v0.12.0 release checklist

## Packet Capture

- [x] Standalone captures run outside the web request, survive navigation, and
  expose live status, stop, download, and delete controls.
- [x] Interface ownership, BPF validation, duration, packet, size, snapshot,
  and promiscuous-mode limits are enforced server-side.
- [x] Packet Capture is reusable as an automation action and retained PCAPs
  participate in run ZIP download, deletion, and retention.
- [x] Standalone and automated PCAP storage shares the artifact quota and
  minimum free-space reserve.
- [x] Live, completed, and datastore PCAP inspection exposes bounded header
  summaries without rendering packet payloads.
- [x] Completed captures copy into a selected datastore folder without tying
  the retained copy to capture-history deletion.

## Product and compatibility

- [x] Wake-on-LAN packets, target parsing, interface selection, bounded repeats,
  custom broadcast/relay destinations, optional confirmation, access control,
  audit redaction, activity metrics, saved groups, and profile backup behavior
  have automated coverage.
- [x] Wake-on-LAN clearly states that successful local UDP delivery does not
  prove that remote infrastructure forwarded or honored a magic packet.
- [x] Multi-Ping was validated on Linux with the standard system-ping fallback
  while fping was absent, then with high-capacity mode after fping installation
  and a toolkit restart.
- [x] Persistent Multi-Ping cadence, graph restoration, minimize/restore, dock
  actions, and bounded server-side history have automated and operator
  validation.
- [x] Persistent SNMP interface monitoring has real-device validation in
  addition to automated session, secret-exclusion, counter, cadence, and route
  coverage.
- [x] Certificate Automation remains labeled Beta in navigation, the tool UI,
  built-in Help, README, and structured release notes.
- [x] v0.12.0 introduces no incompatible migration of existing databases,
  profiles, or configuration. Live monitoring uses a separate owner-only
  transient session store.

## Release candidate gates

- [x] Build the v0.12.0 bundle from the release-preparation commit and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [x] Pass pull-request CI on Ubuntu 3.10, Ubuntu 3.13, macOS 3.13, repository
  checks, and the dependency audit.
- [ ] After approval and squash merge, pass merged-main CI before creating the
  tag.
- [ ] Create and push the exact annotated `v0.12.0` tag only after every
  preceding gate is complete and the project owner explicitly approves it.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the release contains `twn-toolkit-v0.12.0.zip` and
  `twn-toolkit-v0.12.0.zip.sha256` before testing production discovery.
- [ ] From a production v0.11.1 installation, discover and install v0.12.0;
  verify recovery-point creation, web/scheduler/supervisor health, live-tool
  cleanup or restoration, enabled services, audit history, and upgrade status
  after restart.
- [ ] Exercise rollback to the matched v0.11.1 recovery point and confirm the
  prior code and instance data return healthy.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
