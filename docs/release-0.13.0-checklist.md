# v0.13.0 release checklist

## Automation reliability and composition

- [x] Scheduled occurrences use durable SQLite claims, renewable leases,
  expired-claim recovery, bounded infrastructure retries, queue limits, and
  overlap protection.
- [x] Check intervals and reusable calendar schedules are distinct run modes
  with explicit missed-occurrence policy and next-run visibility.
- [x] ALL and ANY groups evaluate multiple reusable conditions in one claimed
  worker run and retain evidence for every member.
- [x] Existing single-condition automations load as compatible one-member ALL
  groups without losing definitions, history, or enabled state.
- [x] Ping Quality and DNS Performance conditions enforce bounded inputs,
  expose per-target/per-resolver evidence, and participate in debounce,
  recovery, and cooldown state handling.

## Packet Capture

- [x] Standalone captures run outside the web request, survive navigation, and
  expose live status, stop, download, delete, and datastore-save controls.
- [x] Interface ownership, BPF validation, duration, packet, size, snapshot,
  and promiscuous-mode limits are enforced server-side.
- [x] Packet Capture is reusable as an automation action; captures can
  participate in run ZIP download and retention or save directly beneath a
  selected datastore folder.
- [x] Standalone and automated PCAP storage shares the artifact quota and
  minimum free-space reserve.
- [x] Live, completed, and datastore PCAP inspection uses a floating,
  minimizable, auto-scrolling window and exposes bounded header summaries
  without rendering packet payloads.
- [x] Local Datastore invokes PCAP inspection directly without requiring
  navigation through Packet Capture.
- [x] Standalone saves accept custom filenames, automation patterns support
  timestamp, action, and interface tokens, and collisions never overwrite
  existing captures.
- [x] Recent standalone captures use collapsed summary cards by default while
  active and explicitly focused captures remain open.

## Email delivery and administration

- [x] SMTP settings support STARTTLS, implicit TLS, and deliberate plaintext;
  certificate verification; encrypted write-only passwords; sender identity;
  bounded timeouts; and a connection test.
- [x] Email actions validate recipients, render bounded metadata templates, and
  never attach collected files or PCAPs.
- [x] Retained email results omit the message body and preserve delivery status,
  subject, recipient counts, and message ID.
- [x] System Settings is separated into System, Email, Operations, and Accounts
  & access views with category-preserving form redirects.
- [x] Updates & Recovery is separated into Updates, Recovery points, and
  Profile backups with advanced and destructive controls progressively
  disclosed.

## Product and compatibility

- [x] v0.13.0 introduces compatible numbered migrations for automation claims,
  schedules, run modes, and condition groups without replacing existing
  application databases, profiles, or configuration.
- [x] Packet capture uses the host's existing packet/BPF permissions and never
  installs capture software, invokes sudo, or broadens operating-system access.
- [x] Certificate Automation remains labeled Beta in navigation, the tool UI,
  built-in Help, README, and structured release notes.
- [x] Built-in Help, README, Quick Start, focused automation/packet-capture
  documentation, and structured release notes describe the shipped behavior.

## Release candidate gates

- [x] Build the v0.13.0 bundle from the release-preparation commit and verify
  its internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass pull-request CI on Ubuntu 3.10, Ubuntu 3.13, macOS 3.13, repository
  checks, and the dependency audit.
- [ ] After approval and squash merge, pass merged-main CI before creating the
  tag.
- [ ] Create and push the exact annotated `v0.13.0` tag only after every
  preceding gate is complete and the project owner explicitly approves it.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the release contains `twn-toolkit-v0.13.0.zip` and
  `twn-toolkit-v0.13.0.zip.sha256` before testing production discovery.
- [ ] From a production v0.12.0 installation, discover and install v0.13.0;
  verify recovery-point creation, web/scheduler/supervisor health, enabled
  services, automation migrations, audit history, and upgrade status after
  restart.
- [ ] Exercise rollback to the matched v0.12.0 recovery point and confirm the
  prior code and instance data return healthy.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
