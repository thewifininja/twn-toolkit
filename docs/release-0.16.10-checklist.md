# v0.16.10 release checklist

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

## Lifecycle and compatibility

- [x] Owner-only boot-generation, web-generation, pause, resume, and transfer
  markers preserve start, stop, restart, listener settings, startup events, and
  return-after-reboot behavior.
- [x] The coordinator retains upgrade, rollback, recovery, validation-only
  process sets, operation-lock finalization, and old-launcher compatibility.
- [x] Recovery snapshots omit only recreated process-state artifacts so a live
  coordinator PID transition cannot race `copytree`; persistent databases and
  WAL files, profiles, captures, certificates, logs, and datastore data remain
  covered by the integrity manifest.
- [x] Existing macOS installations require one explicit
  `sudo ./twn service install` after the v0.16.10 code upgrade; manual startup,
  Linux systemd, databases, profiles, automations, and stored data are unchanged.
- [x] Aggregate service health requires the connector, coordinator, and every
  core direct job while disabled transfer jobs are not falsely reported as
  failures.

## Evidence and documentation

- [x] Record the v0.16.8 production split result: with the CIDR exception,
  scheduled PCAP plus SSH succeeded on 5 of 5 switches; after CIDR removal and
  reboot, PCAP succeeded while SSH returned errno 65.
- [x] Update built-in release notes, README, autostart guidance, incident notes,
  refactor backlog, continuity guidance, and version assertions for v0.16.10.
- [x] Pass native build/signature checks, shell syntax, focused connector,
  service, network-tool, and upgrade tests, then the complete test suite after
  final release metadata and documentation edits.
- [x] Build and validate the v0.16.10 production-test bundle as an upgrade from
  the production v0.16.9 candidate, including its generated SHA-256 checksum.

## Production acceptance without the CIDR fallback

- [ ] Install the verified v0.16.10 code bundle while leaving the Ethernet CIDR
  exception absent, then run `sudo ./twn service install` once.
- [ ] Verify all eight property lists and the native connector are root-owned;
  confirm the connector has no `UserName`, while Gunicorn, automation,
  supervisor, and enabled transfer workers remain UID 501 direct jobs.
- [ ] Verify the Unix socket is mode 0600 and owned by the configured service
  UID, and that System Diagnostics reports **Protected TCP connector · Ready**.
- [ ] Verify toolkit TCP Scanner access to `192.168.1.101:22`, then complete a
  parallel PCAP plus five-switch SSH automation from the direct scheduler.
- [ ] Restart the Mac and repeat toolkit TCP and scheduled PCAP plus SSH from a
  cold boot without an interactive Terminal launch.
- [ ] If the connector path still returns errno 65, restore only
  `192.168.1.0/24`, restart the Mac, retain the CIDR as the production fallback,
  and do not publish the fix as GA.
- [ ] Pass release-preparation and merged-main CI before creating an annotated
  tag or publishing any GitHub release.

Do not tag or publish v0.16.10 until the CIDR-free production acceptance and
cold-boot gates pass.
