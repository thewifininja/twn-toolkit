# v0.21.1 release checklist

## Scope

- [x] Repair Linux LLDP Lab observation when the hardened toolkit systemd unit
  suppresses Debian's setuid-based `lldpcli` transition with
  `NoNewPrivileges=true`.
- [x] Detect the installed `lldpcli` execution group, setuid account group, and
  local `lldpd` socket group without granting root to the toolkit service.
- [x] Render those package-owned groups as systemd `SupplementaryGroups` while
  preserving the normal service user and bounded network capabilities.
- [x] Detect standard Linux sbin installations and give an actionable service
  reinstall command when the socket remains inaccessible.

## Platform and compatibility boundary

- [x] Reproduce the failure on Raspberry Pi OS with `lldpcli` 1.0.18,
  `NoNewPrivileges=true`, and a permission denial on `/run/lldpd.socket`.
- [x] Validate the scoped group repair under the same hardened systemd boundary
  and decode the live FortiSwitch neighbor on `eth0`.
- [x] Install the repaired unit on the field-test Pi and confirm the web,
  automation, supervisor, Raspberry Pi network broker, and LLDP daemon remain
  active.
- [x] Add no Python dependency, database migration, profile-format change, or
  macOS service change and keep the normal `v0.9.0` minimum upgrade boundary.
- [x] Require one explicit
  `sudo ./twn service install --network-capabilities` after upgrade on existing
  Linux service installations that use LLDP Lab.

## Validation

- [x] Pass the focused service and LLDP suites: 51 tests passed.
- [x] Pass the complete unittest discovery suite: 797 tests passed.
- [x] Pass the complete release-preparation pytest suite: 822 passed, 9
  skipped, and 308 subtests passed.
- [x] Run the pinned dependency audit with only the repository's two documented
  advisory exceptions: no known vulnerabilities found.
- [x] Build and validate the v0.21.1 upgrade bundle with 414 manifested files,
  the `v0.9.0` minimum upgrade boundary, and a matching SHA-256 digest.
- [x] Pass release PR `#145` CI run `32478422968` on Ubuntu Python
  3.10/3.13 and macOS Python 3.13, including repository checks and dependency
  audit.
- [x] Squash-merge release PR `#145` as commit `6d861c5` and pass merged-main
  CI run `32478613617`.

## Publication gate

- [ ] Create and push the annotated `v0.21.1` tag only after every validation
  item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.21.1.zip` and `twn-toolkit-v0.21.1.zip.sha256` before
  announcing upgrade availability.

Stop before tagging unless every validation item above is complete.
