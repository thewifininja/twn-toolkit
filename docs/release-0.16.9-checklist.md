# v0.16.9 release checklist

## Direct macOS LaunchDaemons

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

## Lifecycle and compatibility

- [x] Owner-only boot-generation, web-generation, pause, resume, and transfer
  markers preserve start, stop, restart, listener settings, startup events, and
  return-after-reboot behavior.
- [x] The coordinator retains upgrade, rollback, recovery, validation-only
  process sets, operation-lock finalization, and old-launcher compatibility.
- [x] Existing macOS installations require one explicit
  `sudo ./twn service install` after the v0.16.9 code upgrade; manual startup,
  Linux systemd, databases, profiles, automations, and stored data are unchanged.
- [x] Aggregate service health requires the coordinator and every core direct
  job while disabled transfer jobs are not falsely reported as failures.

## Evidence and documentation

- [x] Record the v0.16.8 production split result: with the CIDR exception,
  scheduled PCAP plus SSH succeeded on 5 of 5 switches; after CIDR removal and
  reboot, PCAP succeeded while SSH returned errno 65.
- [x] Update built-in release notes, README, autostart guidance, incident notes,
  refactor backlog, continuity guidance, and version assertions for v0.16.9.
- [x] Pass shell syntax, 49 focused service/upgrade tests, and the complete
  pytest suite after the final release metadata and documentation edits: 621
  passed, 6 skipped, and 214 subtests passed.
- [x] Build and validate the exact v0.16.9 production-test bundle against
  v0.16.8, including its generated SHA-256 checksum.

## Production acceptance without the CIDR fallback

- [ ] Install the verified v0.16.9 code bundle while leaving the Ethernet CIDR
  exception absent, then run `sudo ./twn service install` once.
- [ ] Verify all seven property lists are root-owned and the Gunicorn master,
  automation worker, supervisor, and enabled transfer workers have launchd as
  their direct parent.
- [ ] Verify toolkit TCP Scanner access to `192.168.1.101:22`, then complete a
  parallel PCAP plus five-switch SSH automation from the direct scheduler.
- [ ] Restart the Mac and repeat toolkit TCP and scheduled PCAP plus SSH from a
  cold boot without an interactive Terminal launch.
- [ ] If errno 65 returns, restore only `192.168.1.0/24`, restart the Mac, retain
  the CIDR as the production fallback, and do not publish the fix as GA.
- [ ] Pass release-preparation and merged-main CI before creating an annotated
  tag or publishing any GitHub release.

Do not tag or publish v0.16.9 until the CIDR-free production acceptance and
cold-boot gates pass.
