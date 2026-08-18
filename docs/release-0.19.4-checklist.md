# v0.19.4 release checklist

## Scope

- [x] Add Console as a third Remote Terminal transport alongside SSH and
  Telnet.
- [x] Discover supported local USB UART, OS-paired Bluetooth serial, and other
  console devices on macOS and Linux.
- [x] Support Quick Connect and saved console definitions with reusable serial
  line settings and stable hardware identity.
- [x] Reuse persistent terminal sessions, pop-out windows, scrollback,
  Datastore retention, and active-case transcript evidence.
- [x] Enforce exclusive physical-adapter ownership across operators and web
  workers.
- [x] Preserve console connection metadata through encrypted configuration
  backup review and import.
- [x] Document macOS, Linux, and Raspberry Pi deployment and permission
  behavior.

## Platform and compatibility boundary

- [x] Validate a real FT232R USB UART session on macOS.
- [x] Validate the same FT232R USB UART through a systemd-managed Raspberry Pi
  installation whose service account receives dialout group access.
- [x] Confirm OS-level Bluetooth pairing remains outside the toolkit and only
  serial endpoints already exposed by the operating system are discovered.
- [x] Add pinned pyserial 3.5 through the existing requirements installation
  path without changing service definitions, capabilities, native helpers, or
  installer topology.
- [x] Add only backward-compatible Remote Terminal database columns and retain
  existing SSH and Telnet connections, credentials, sessions, cases, and
  configuration backups.
- [x] Confirm direct upgrades from v0.19.3 require no stepped release.

## Validation

- [x] Run the complete feature-branch suite: 773 passed, 9 skipped, and 297
  subtests passed.
- [x] Pass feature PR `#133` CI run `32092064896` on Ubuntu Python 3.10/3.13
  and macOS Python 3.13, including repository checks and dependency audit.
- [x] Squash-merge feature PR `#133` as commit
  `92882ce` and pass merged-main CI run `32092208074`.
- [x] Run the complete test suite from the exact v0.19.4 release-preparation
  source: 773 passed, 9 skipped, and 297 subtests passed; the pinned dependency
  audit found no known vulnerabilities with two documented advisories ignored
  by policy.
- [x] Build and validate the exact v0.19.4 upgrade bundle with 396 manifested
  files and a matching SHA-256 digest.
- [x] Pass release-preparation PR `#134` CI run `32092742575`, squash-merge it
  as commit `f25db13541263b577a46936bc3703312d453e872`, and pass merged-main CI
  run `32092877151`.

## Publication gate

- [ ] Create and push the annotated `v0.19.4` tag only after every validation
  item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.19.4.zip` and `twn-toolkit-v0.19.4.zip.sha256` before
  announcing upgrade availability.

Stop before tagging unless every validation item above is complete.
