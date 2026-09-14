# v0.26.1 release checklist

Patch release of current main since published v0.26.0. Publication evidence belongs
in the [GitHub release](https://github.com/thewifininja/twn-toolkit/releases/tag/v0.26.1).
Unchecked gates reflect the committed candidate state.

## Scope

- [x] Fix case-report rendering of DNS load-test and other metric-only results.
  Existing saved evidence needs no migration or test rerun.
- [x] Read-only single-gate/Fabric DHCP inventory, grouped browsing and pagination.
- [x] Discovered Fabric targets for supported FortiGate exports, AP/switch actions,
  ordering and wireless history, with hostname-based selection.
- [x] Experimental Switch Loop Inspector, including optional bounded root-gate SSH
  diagnostics and suspicious same-switch LLDP cable evidence.
- [x] Appliance profile-history placement, task spacing and field-label spacing.
- [x] README, Quick Start, built-in Help/release notes and version assertions updated.

## Compatibility and acceptance

- Upgrade Mainframe and Agents together and reload browser pages before using
  Fabric jobs. This patch adds no database migration or dependency changes.
- Existing v0.26.0 case reports retain their original data; reopening renders the
  saved results. Regression coverage executes DNS jobs into a case and verifies
  report rendering without replaying DNS, plus the shared DHCP metric fallback.
- DHCP inventory and Loop Inspector remain investigation-only. Loop Inspector is
  explicitly experimental: downstream SSH, exhaustive firmware coverage and
  automatic ring/chord identification are not claimed. Findings require review.
- Fabric targeting uses discovered paths and strict response identity checks.
  Drain or cancel Fabric jobs before rollback to older workers that ignore target
  selection. Older workers do not support Loop Inspector.
- Prior feature validation includes live read-only Fabric/loop observations and
  an operator-created same-switch cable loop; live downstream writes were not
  performed. Automated write preflight/acknowledgment/no-replay coverage applies.
- User requested this patch to retrieve an existing v0.26.0 case report. No claim
  of new fleet-scale, Fedora, appliance/CA or physical-device acceptance is made.
- Existing minimum direct upgrade boundary remains v0.9.0; see
  [upgrade and recovery](upgrade-recovery.md) for older updater/service exceptions.
- Future beta builds require explicit prerelease versions and matching tags after
  updater support is implemented; see [beta policy](beta-releases.md).

## Candidate validation

- [ ] Complete suite in a fresh environment using hash-locked dependencies.
- [x] Dependency provenance, shell syntax and exact-source bundle/checksum checks,
  including exclusion of private/runtime files.
- [ ] Reviewed release PR and all six candidate CI checks.
- [ ] Merged-main CI and equality with the reviewed candidate tree.

## Publication

- [ ] Annotated v0.26.1 tag on verified main, matching APP_VERSION.
- [ ] All tag CI checks passed before publication.
- [ ] Release published; Release upgrade bundle workflow succeeded.
- [ ] Published ZIP/checksum verified against tagged source; normal stable
  discovery offers v0.26.1 to v0.26.0 installations.

Follow [the release process](../CONTRIBUTING.md#releases). Record post-commit
checks in the release/private continuity without moving the published tag.
