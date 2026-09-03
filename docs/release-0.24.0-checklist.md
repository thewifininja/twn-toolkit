# v0.24.0 release checklist

## Scope

- [x] Add resilient agent-to-standalone transitions, an in-product restart
  action, reliable Mainframe escape recovery, and an available-agent selector.
- [x] Add Global, Admins Only, and Private Remote Terminal definition
  visibility, migrate existing definitions to Admins Only, and correct
  host-specific credential-name reuse.
- [x] Add stable IPv4 and IPv6 interface-change automations with live interface
  choices, private baselines, debounce, bounded evidence, and opt-in noisy
  address classes.
- [x] Add Arch and Omarchy service permission handling for serial devices and
  support the Arch lldpd control-socket layout.

## Platform and compatibility boundary

- [x] Add no Python dependency and retain the normal `v0.9.0` minimum direct-
  upgrade boundary; no stepped release is required.
- [x] Automatically migrate existing Remote Terminal definitions to Admins
  Only without changing their connection contents.
- [x] Require no general service reinstall. Arch or Omarchy installations that
  need serial access can rerun `sudo ./twn service install` to apply the serial-
  group membership correction.
- [x] Keep interface baselines local to each automation and create them silently
  on first evaluation without producing a false change event.

## Local validation

- [x] Pass the complete v0.24.0 release-preparation suite: 962 tests passed, 1
  expected skip, and 341 subtests passed.
- [x] Run the dependency audit with only the repository's two documented
  advisory exceptions: no known vulnerabilities found.
- [x] Build and validate the v0.24.0 upgrade bundle with 458 archive entries,
  457 manifest payload files, the `v0.9.0` minimum upgrade boundary, and a
  matching SHA-256 checksum sidecar.
- [x] Validate version metadata, built-in Help, README, release notes, platform
  compatibility, visibility migration, distributed recovery, and interface
  automation coverage.

## Pull-request and merged-main gates

- [x] Pass feature PR #180 in CI run `33711875436` on Ubuntu Python 3.10/3.13
  and macOS Python 3.13, including repository checks and dependency audit, then
  squash-merge it as `e42b979424625e79b77b3f309d84b01d86623593`.
- [x] Pass v0.24.0 release-preparation PR #181 in CI run `33752918973` and
  squash-merge it as `10d3c1bf12c0fd517a354613171fdf5d8b943a28`.
- [x] Pass merged-main CI run `33753284484` on Ubuntu Python 3.10/3.13 and
  macOS Python 3.13, including repository checks and dependency audit.

## Publication gate

- [ ] Create and push the annotated `v0.24.0` tag only after every validation
  and merged-main item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both `twn-toolkit-v0.24.0.zip` and
  `twn-toolkit-v0.24.0.zip.sha256` before announcing upgrade availability.

Stop before tagging unless every validation and merged-main item above is
complete.
