# v0.10.0 release checklist

This checklist records the release-specific gates for the SNMP monitoring,
audit-completeness, and hardening milestone. General release mechanics remain
in `CONTRIBUTING.md`.

## Product and compatibility

- [x] SNMP monitor discovers saved hosts and standard IF-MIB interfaces, builds
  a bounded 20-interface set, and keeps browser-lived graph history.
- [x] Monitor start/stop boundaries are auditable while discovery and polling
  noise is suppressed.
- [x] Every mutating route is intentionally classified by the audit policy;
  the pending set is empty.
- [x] High-impact packet replay, FortiGate bulk rename, and switch reorder
  workflows require preview and explicit confirmation.
- [x] The v0.9.1 fixture upgrades without losing representative settings,
  profiles, automation definitions, or operational state.
- [x] Pre-upgrade backup, verification, and full-instance rollback are
  documented.
- [x] No configuration or schema incompatibility is introduced by v0.10.0.

## Reliability, security, and interface

- [x] Installer refresh of an active installation restarts managed processes.
- [x] Web, scheduler, supervisor, and enabled transfer listeners recover after
  a managed restart.
- [x] Traceroute, packet replay, SCP, and FortiAuthenticator pagination have
  explicit duration, volume, cancellation, or traversal bounds.
- [x] Cross-origin mutations are rejected and authenticated pages use defensive
  response headers and no-store behavior.
- [x] Runtime dependencies are pinned and audited in CI; reviewed exceptions
  and their mitigations are documented.
- [x] Common token, private-key, and tracked-secret patterns are absent from
  committed source; runtime instance data remains ignored.
- [x] SNMP actions retain consistent spacing and touch targets, wrap at phone
  width, and create no horizontal overflow.
- [x] Representative Dashboard, Help, SNMP, Packet Replay, and Automation pages
  pass phone-width overflow and basic accessible-name checks; keyboard focus is
  visibly indicated.

## Documentation and release mechanics

- [x] `APP_VERSION`, README, structured release notes, built-in Help, Quick
  Start behavior, continuity notes, upgrade guidance, and security guidance
  agree on v0.10.0 behavior.
- [x] Complete local test suite passes on the release commit (294 tests).
- [x] Pull-request CI passes on Ubuntu Python 3.10/3.13 and macOS Python 3.13,
  including repository checks and dependency audit.

After these versioned gates are green, squash-merge the release branch, update
the local `main`, create and push the annotated `v0.10.0` tag, wait for tag CI,
then publish and verify the GitHub release from the structured notes.
