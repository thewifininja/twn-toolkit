# v0.17.0 release checklist

## Release scope

- [x] Consolidate the unpublished v0.16.8 through v0.16.11 production
  candidates into a minor release because the macOS service topology and
  bounded privileged connector are new operational architecture.
- [x] Keep the application, automation scheduler, Paramiko, credentials,
  commands, transfers, and stored data under the configured non-root account.
- [x] Limit the native helper to outbound TCP connection setup and a fixed
  opaque relay as root for the configured service UID over an owner-only Unix
  socket without parsing, logging, persisting, authenticating, or executing
  application traffic.
- [x] Preserve existing manual startup and Linux behavior without installing or
  invoking the macOS connector.

## Upgrade and rollback safety

- [x] Snapshot top-level SQLite databases with SQLite's online backup API rather
  than raw main/WAL file copying.
- [x] Consolidate snapshot journal state and require `PRAGMA quick_check` on the
  live source, completed recovery copy, post-manifest restore input, and final
  installed databases.
- [x] Reject malformed source databases before changing code and restart the
  untouched installation when recovery-point creation fails.
- [x] Preserve the malformed production database and document the exact healthy
  displaced source used for recovery.
- [x] Remove coordinator, worker, and connector property lists, the root helper,
  Unix socket, and launchd activation state during macOS service uninstall.
- [x] Discover managed checkout roots from surviving worker property lists so a
  missing coordinator cannot strand service artifacts.
- [x] Document the cross-topology downgrade rule: uninstall with v0.17.0 code,
  restore the matched v0.16.7-or-older code and instance, then install the older
  service definition.

## Automated verification

- [x] Prove a recovery point contains committed rows that exist in a live WAL
  and does not depend on copied WAL/shared-memory sidecars.
- [x] Prove recovery creation rejects a malformed live database and removes the
  incomplete recovery directory.
- [x] Prove restore verification rejects a malformed database even when its
  integrity manifest matches the malformed bytes.
- [x] Prove macOS uninstall removes every new system artifact and runtime marker
  when only direct worker property lists remain.
- [x] Retain only the bounded failed installer stage and exit status while
  continuing to discard package-manager output that may contain credentials.
- [x] Reproduce the missing automation PID marker after a successful direct-job
  handoff, distinguish the current scheduler from the historical database log,
  and add exact-instance cleanup for direct and daemonized workers.
- [x] Add a bounded post-handoff readiness wait that repairs an untracked
  scheduler or supervisor generation before leaving the service degraded.
- [x] Reproduce the transient production launchd reinstall failure, wait for
  every old job to leave the system domain, and retry one partial bootstrap
  automatically before surfacing a bounded failure.
- [x] Reproduce the final descriptor-handoff gap: raw and bare Paramiko probes
  succeed from Terminal, but the background scheduler loses every SSH banner;
  replace the transferred remote descriptor with a bounded opaque relay.
- [x] Reproduce the privilege-drop timing gap: the intermediate relay passes a
  manual 5-of-5 run, then timed runs fall to 4 of 5 and 2 of 5 with one stranded
  child per failed banner; retain only the fixed relay loop as root and add
  five-second idle half-close plus default-signal cleanup.
- [x] Pass native build/signature checks, shell syntax, focused connector,
  service, network-tool, automation, and upgrade tests after the relay change.
- [x] Pass the complete test suite after the final root-retained relay,
  launchd-race, version, and documentation edits: 637 passed, 7 skipped, and
  214 subtests passed on the release-preparation Mac.

## Production acceptance without the CIDR fallback

- [x] Recover the production automation database from the newest healthy
  displaced pre-rollback copy; verify every live SQLite database and all core
  services before continuing.
- [x] Bootstrap the safe recovery-point implementation onto the v0.16.10
  production candidate before asking that older updater to install v0.17.0.
- [x] Install the verified v0.17.0 bundle without reinstalling the unchanged
  v0.16.10 connector helper or restoring the CIDR exception.
- [x] Reconcile production to the 345-file descriptor candidate (SHA-256
  `c1ef8be68dbd5191bb1ccb1f9c775a3dbab663ecf774d48763b778843aaf8f9b`)
  after verifying recovery point `20260810-134833-72604bc5`.
- [x] Verify and reconcile the intermediate 346-file privilege-dropped relay bundle
  (SHA-256
  `7d2134081c46896d5b871ad0e7c1eaff37c0057e6f0f66c82c593bacc9b928a2`)
  after verifying recovery point `20260810-143245-e9d1a30e`; reinstall the
  root helper and direct launchd job set.
- [x] Verify the reconciled checkout has zero manifest mismatches, every live
  SQLite database passes integrity checks, and no upgrade operation lock
  remains.
- [x] Complete a normal production restart through the revised handoff path;
  confirm fresh web, scheduler, supervisor, coordinator, and toolkit PID
  markers plus an Active toolkit and Ready protected TCP connector.
- [x] Complete simultaneous PCAP and five-switch SSH from a manual automation:
  capture 7,509 packets on `en0` in 30.0 seconds and collect SSH output from
  all 5 of 5 switches without the CIDR exception.
- [x] Sample the intermediate connector during the successful manual run:
  retain only the listener as root and observe each live relay child under
  `admin`, with the owner-only socket still `admin:staff` mode `0600`.
- [x] Run two calendar-triggered PCAP/SSH automations from the service: PCAP
  succeeds both times, while SSH succeeds on 4 of 5 and then 2 of 5 hosts;
  correlate the variable banner failures one-for-one with stranded admin relay
  children and invalidate the privilege-dropped candidate.
- [ ] Repeat from a scheduled or condition-triggered automation with the final
  root-retained relay.
- [ ] Restart the Mac and repeat diagnostics plus scheduled PCAP and SSH from a
  cold boot without an interactive Terminal launch.
- [x] Audit `/Library/LaunchDaemons`, `/Library/PrivilegedHelperTools`, the
  connector socket, service ownership, and toolkit runtime markers: property
  lists and helper are root-owned, the helper is executable, the socket is
  `admin:staff` with owner-only access, and all direct-job markers are current.

## Publication gate

- [x] Review the production installer failures after database rollback safety
  is in place; retain bounded stage/exit diagnostics, and harden the launchd
  unload/bootstrap transition without exposing package-manager credentials.
- [x] Build and validate the exact 345-file descriptor candidate and matching
  SHA-256 sidecar from the release-preparation source.
- [x] Build and validate the intermediate 346-file privilege-dropped relay
  bundle and matching SHA-256 sidecar.
- [x] Build and validate the final 346-file root-retained relay bundle and
  matching SHA-256 sidecar: SHA-256
  `5a7c3c5d9e2716f224e92913333264732c70034f37ac2acedbbb2b5cf86bec8a`.
- [ ] Pass release-preparation and merged-main CI.
- [ ] Create and push the annotated `v0.17.0` tag only after project-owner
  approval and all production acceptance checks pass.
- [ ] Verify the published release contains both the ZIP and SHA-256 asset before
  announcing in-app upgrade availability.

Do not tag or publish v0.17.0 until the final root-retained relay passes the
CIDR-free manual, scheduled, cold-boot, recovery, and cleanup gates.
