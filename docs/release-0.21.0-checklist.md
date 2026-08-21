# v0.21.0 release checklist

## Scope

- [x] Add interface-scoped LLDP neighbor observation through the host `lldpd`
  service with decoded identity, management, capability, VLAN, and LLDP-MED
  fields.
- [x] Add explicit local `lldpd` receive-only and normal-transmit controls
  outside active emulation sessions.
- [x] Add reusable generic endpoint, VoIP phone, and bridge personas with exact
  preview, duplication, custom organizational TLVs, and explicit authorization.
- [x] Import LLDP identities from bounded classic-PCAP uploads or Local
  Datastore captures, group repeated speakers, and require review before save
  or transmission.
- [x] Bound each interface to one timed transmit session, send a TTL-zero
  shutdown PDU, restore prior local daemon state, and retain case lifecycle
  summaries and evidence.
- [x] Expose `toolkit.version` to startup automation templates and clarify safe
  Raspberry Pi service repair without dropping existing network capabilities.

## Platform and compatibility boundary

- [x] Field-test LLDP observation, capture-led persona import, selected-interface
  transmission, local-advertisement suppression, and TTL-zero withdrawal on
  macOS using an `en6` FortiSwitch lab connection.
- [x] Confirm a captured FortiSwitch identity can create a dynamic Auto-ISL
  trunk and that stopping transmission withdraws the dynamic trunk after the
  adjacent switch processes the shutdown/expiry condition.
- [x] Confirm LLDP alone did not mutate the separately configured static ISL in
  the exercised lab, without treating that result as a guarantee across switch
  models or software releases.
- [x] Keep observation dependent on optional `lldpd`/`lldpcli`, Linux raw-frame
  transmission on the existing bounded network-capability service option, and
  macOS transmission on the existing BPF permission model.
- [x] Add no Python dependency or database migration and keep the normal
  `v0.9.0` minimum upgrade boundary so no stepped release is required.

## Feature validation

- [x] Run the LLDP feature-branch suite: 817 passed, 9 skipped, and 308 subtests
  passed.
- [x] Pass LLDP feature PR `#141` CI run `32442350505` on Ubuntu Python
  3.10/3.13 and macOS Python 3.13, including repository checks and dependency
  audit.
- [x] Squash-merge LLDP feature PR `#141` as commit `e4244ad` and pass
  merged-main CI run `32442485248`.
- [x] Run the Pi service-guidance branch suite: 819 passed, 9 skipped, and 308
  subtests passed.
- [x] Pass Pi service-guidance PR `#142` CI run `32442859126`, squash-merge it
  as commit `7d32ee4`, and pass merged-main CI run `32442989947`.

## Release-preparation validation

- [x] Run the complete test suite from the v0.21.0 release-preparation source:
  819 passed, 9 skipped, and 308 subtests passed.
- [x] Run the pinned dependency audit with only the repository's two documented
  advisory exceptions: no known vulnerabilities found.
- [x] Build and validate the v0.21.0 upgrade bundle with 413 manifested files,
  the `v0.9.0` minimum upgrade boundary, and a matching SHA-256 digest.
- [x] Pass release-preparation PR `#143` CI run `32443532741`, squash-merge it
  as commit `e2cb61e`, and pass merged-main CI run `32443673744`.

## Publication gate

- [ ] Create and push the annotated `v0.21.0` tag only after every validation
  item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.21.0.zip` and `twn-toolkit-v0.21.0.zip.sha256` before
  announcing upgrade availability.

Stop before tagging unless every validation item above is complete.
