# v0.16.11 release checklist

Historical production candidate only. Do not tag or publish this version. Its
network descriptor fix is retained in v0.17.0, while production upgrade testing
exposed a raw SQLite recovery-copy defect that v0.17.0 corrects before GA.

## Direct unprivileged macOS LaunchDaemons

- [x] Render a stable coordinator plus direct web, automation, supervisor,
  TFTP, SFTP/SCP, and FTP system LaunchDaemon property lists.
- [x] Every direct worker enters through `twn launchd-run ROLE`, avoids daemon
  mode, and `exec`s the final Gunicorn or Python process without an intervening
  fork so launchd remains its actual parent.
- [x] Core and transfer jobs use positive owner-only activation markers with no
  run-at-load fallback; stop and rollback remove them so older restored code
  leaves the additional jobs dormant.
- [x] The toolkit remains owned by the selected non-root service account and
  never runs the complete application as root.

## Protected TCP connector

- [x] Record the failed candidate evidence: direct UID 501 workers with PPID 1
  and `UserName=admin` still receive errno 65 on production macOS 15.1.1.
- [x] Record controlled boundary probes: a root LaunchDaemon parent spawning an
  unprivileged Python child still fails, while the process calling `connect()`
  as root succeeds; unload both temporary jobs afterward.
- [x] Add a universal native connector whose root authority is limited to TCP
  connection setup and descriptor handoff over a mode-0600 Unix socket.
- [x] Restrict requests to the configured service UID with `getpeereid`, bound
  protocol lengths and timeouts, and pass only the connected descriptor with
  `SCM_RIGHTS`; credentials, SSH commands, HTTP payloads, and output remain in
  the unprivileged caller.
- [x] Route managed macOS Python TCP sockets through the connector while
  bypassing loopback, nonblocking sockets, manual launches, and Linux.
- [x] Install the helper and its no-`UserName` root LaunchDaemon atomically,
  include it in aggregate service health and cleanup, and report connector
  readiness under System Diagnostics.
- [x] Reproduce the v0.16.10 production banner failure and prove that the raw
  `SCM_RIGHTS` descriptor receives the switch banner while overlaying it on the
  Python placeholder produces EOF.
- [x] Adopt the returned descriptor directly, preserve the caller timeout, and
  add socket-ownership plus real-TCP bidirectional regression coverage.

## Lifecycle and compatibility

- [x] Owner-only boot-generation, web-generation, pause, resume, and transfer
  markers preserve start, stop, restart, listener settings, startup events, and
  return-after-reboot behavior.
- [x] The coordinator retains upgrade, rollback, recovery, validation-only
  process sets, operation-lock finalization, and old-launcher compatibility.
- [ ] Historical candidate copied persistent SQLite main and WAL files through
  `copytree`. Production rollback proved that was not an atomic database
  snapshot; v0.17.0 replaces it with verified SQLite online backups.
- [x] Hosts predating the connector require one explicit
  `sudo ./twn service install` after installing v0.16.10 or newer; a host that
  already installed the v0.16.10 helper needs no repeat install for v0.16.11.
  Manual startup, Linux, databases, profiles, automations, and data are unchanged.
- [x] Aggregate service health requires the connector, coordinator, and every
  core direct job while disabled transfer jobs are not falsely reported as
  failures.

## Evidence and documentation

- [x] Record the v0.16.8 production split result: with the CIDR exception,
  scheduled PCAP plus SSH succeeded on 5 of 5 switches; after CIDR removal and
  reboot, PCAP succeeded while SSH returned errno 65.
- [x] Record v0.16.10 production evidence: connector ready, TCP scanner open,
  raw switch banner received, placeholder overlay EOF, and direct adoption good.
- [x] Update built-in release notes, README, incident notes, continuity guidance,
  and version assertions for v0.16.11.
- [x] Pass native build/signature checks, shell syntax, focused connector,
  service, network-tool, and upgrade tests, then the complete test suite after
  final release metadata and documentation edits.
- [x] Build and validate the v0.16.11 production-test bundle as an upgrade from
  the production v0.16.10 candidate, including its generated SHA-256 checksum.

## Production acceptance without the CIDR fallback

- [x] Install the verified v0.16.10 code bundle while leaving the Ethernet CIDR
  exception absent, then run `sudo ./twn service install` once.
- [x] Verify all eight property lists and the native connector are root-owned;
  confirm the connector has no `UserName`, while Gunicorn, automation,
  supervisor, and enabled transfer workers remain UID 501 direct jobs.
- [x] Verify the Unix socket is mode 0600 and owned by the configured service
  UID, and that System Diagnostics reports **Protected TCP connector · Ready**.
- [x] Verify toolkit TCP Scanner access to `192.168.1.101:22` without the CIDR
  fallback and diagnose the v0.16.10 SSH banner failure independently.
- [ ] Install the verified v0.16.11 code bundle through the normal updater; do
  not reinstall the unchanged root helper or alter the CIDR exception.
- [ ] Complete a parallel PCAP plus five-switch SSH automation manually and
  from the direct scheduler.
- [ ] Restart the Mac and repeat toolkit TCP and scheduled PCAP plus SSH from a
  cold boot without an interactive Terminal launch.
- [ ] If the connector path still returns errno 65, restore only
  `192.168.1.0/24`, restart the Mac, retain the CIDR as the production fallback,
  and do not publish the fix as GA.
- [ ] Pass release-preparation and merged-main CI before creating an annotated
  tag or publishing any GitHub release.

Do not tag or publish v0.16.11 until the CIDR-free production acceptance and
cold-boot gates pass.
