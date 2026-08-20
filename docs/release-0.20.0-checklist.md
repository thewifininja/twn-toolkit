# v0.20.0 release checklist

## Scope

- [x] Detect Raspberry Pi hardware and expose its networking workspace only on
  supported hosts.
- [x] Add NAT access-point, untagged/VLAN bridged-access-point, and Wi-Fi
  client modes through NetworkManager.
- [x] Support open, WPA2/WPA3 Personal, PEAP-MSCHAPv2, and EAP-TLS client
  networks with encrypted write-only secrets and validated certificate
  material.
- [x] Apply privileged network changes through a narrowly scoped root-owned
  broker with confirmation, audit, and automatic rollback.
- [x] Add small, medium, and large Ping graphs plus a compact fleet health grid.
- [x] Add configurable Ping loss, latency, and jitter thresholds with
  hover/focus/touch graph previews and a synchronized standalone results view.

## Platform and compatibility boundary

- [x] Field-test Raspberry Pi NAT, untagged bridge, VLAN 10 bridge, WPA2 PSK
  client mode, rollback, disable/restore, and cold-boot persistence.
- [x] Confirm a tagged wireless bridge remains Layer-2-only, carries client
  DHCP successfully after cold boot, and retains Ethernet management on the
  parent interface.
- [x] Cover PEAP and EAP-TLS with automated validation while recording that a
  suitable live enterprise Wi-Fi network was unavailable for field testing.
- [x] Verify Ping graph sizing, status classification, configurable degraded
  thresholds, grid previews, and the standalone workspace at desktop and phone
  widths.
- [x] Preserve existing Ping profiles with backward-compatible defaults and
  add no Python dependency or database migration.
- [x] Keep the normal `v0.9.0` minimum upgrade boundary so no stepped release
  is required.
- [x] Document that an existing Raspberry Pi installation must run
  `sudo ./twn service install` once after upgrade to install or refresh the
  root-owned NetworkManager broker.

## Feature validation

- [x] Run the Raspberry Pi feature-branch suite: 800 passed, 9 skipped, and
  302 subtests passed.
- [x] Pass Raspberry Pi feature PR `#136` CI run `32326260239` on Ubuntu Python
  3.10/3.13 and macOS Python 3.13, including repository checks and dependency
  audit.
- [x] Squash-merge Raspberry Pi feature PR `#136` as commit `8ab9e91` and pass
  merged-main CI run `32326406524`.
- [x] Run the Ping presentation feature-branch suite: 800 passed, 9 skipped,
  and 303 subtests passed.
- [x] Pass Ping presentation PR `#137` CI run `32329346380` on Ubuntu Python
  3.10/3.13 and macOS Python 3.13, including repository checks and dependency
  audit.
- [x] Confirm the Ping squash merge `edd4fd4` passes merged-main CI run
  `32329495725`.

## Release-preparation validation

- [x] Run the complete test suite from the exact v0.20.0 release-preparation
  source: 800 passed, 9 skipped, and 303 subtests passed.
- [x] Run the pinned dependency audit with only the repository's two documented
  advisory exceptions: no known vulnerabilities found.
- [x] Build and validate the exact v0.20.0 upgrade bundle with 404 manifested
  files, the `v0.9.0` minimum upgrade boundary, and a matching SHA-256 digest.
- [ ] Pass release-preparation PR CI, squash-merge it, and pass merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.20.0` tag only after every validation
  item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.20.0.zip` and `twn-toolkit-v0.20.0.zip.sha256` before
  announcing upgrade availability.

Stop before tagging unless every validation item above is complete.
