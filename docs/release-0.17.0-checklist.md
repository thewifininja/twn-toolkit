# v0.17.0 release checklist

## Release scope

- [x] Consolidate the unpublished v0.16.8 through v0.16.11 production
  candidates into a minor release because the macOS service topology and
  bounded privileged connector are new operational architecture.
- [x] Keep the application, automation scheduler, Paramiko, credentials,
  commands, transfers, and stored data under the configured non-root account.
- [x] Limit the native root helper to outbound TCP connection setup for the
  configured service UID and descriptor handoff over an owner-only Unix socket.
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
- [x] Pass native build/signature checks, shell syntax, focused connector,
  service, network-tool, automation, and upgrade tests.
- [x] Pass the complete test suite after final version and documentation edits:
  632 passed, 7 skipped, and 214 subtests passed on the release-preparation Mac.

## Production acceptance without the CIDR fallback

- [x] Recover the production automation database from the newest healthy
  displaced pre-rollback copy; verify every live SQLite database and all core
  services before continuing.
- [ ] Bootstrap the safe recovery-point implementation onto the v0.16.10
  production candidate before asking that older updater to install v0.17.0.
- [ ] Install the verified v0.17.0 bundle without reinstalling the unchanged
  v0.16.10 connector helper or restoring the CIDR exception.
- [ ] Complete simultaneous PCAP and five-switch SSH from a manual automation.
- [ ] Repeat from a scheduled or condition-triggered automation.
- [ ] Restart the Mac and repeat diagnostics plus scheduled PCAP and SSH from a
  cold boot without an interactive Terminal launch.
- [ ] Audit `/Library/LaunchDaemons`, `/Library/PrivilegedHelperTools`, the
  connector socket, service ownership, and toolkit runtime markers.

## Publication gate

- [ ] Review the production installer failure independently after database
  rollback safety is in place; retain bounded diagnostics without exposing
  package-manager credentials.
- [x] Build and validate the exact 345-file v0.17.0 bundle and matching SHA-256
  sidecar from the release-preparation source.
- [ ] Pass release-preparation and merged-main CI.
- [ ] Create and push the annotated `v0.17.0` tag only after project-owner
  approval and all production acceptance checks pass.
- [ ] Verify the published release contains both the ZIP and SHA-256 asset before
  announcing in-app upgrade availability.

Do not tag or publish v0.17.0 until the CIDR-free manual, scheduled, cold-boot,
recovery, and cleanup gates pass.
