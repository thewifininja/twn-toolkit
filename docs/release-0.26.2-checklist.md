# v0.26.2 release checklist

Patch release since published v0.26.1, adding retained DNS run CSV exports.
Post-commit evidence belongs in the [GitHub release](https://github.com/thewifininja/twn-toolkit/releases/tag/v0.26.2).
Unchecked entries reflect the committed candidate state.

## Scope and compatibility

- [x] Export CSV on completed DNS comparison and load-test run pages.
- [x] Comparisons export all retained rows across pages; load tests export one
  summary row per resolver with counts, throughput, latency and response counts.
- [x] Run identity/timestamps, spreadsheet-safe text, ownership/tool permission
  enforcement and downloads from retained results without DNS replay.
- [x] README, Quick Start, built-in release notes, version assertions and Help
  describe the behavior; shared export conventions documented in UI guidelines.
- Upgrade the instance holding the DNS run and reload browser pages. Existing
  retained runs work immediately. Load tests do not retain individual samples.
- No new schema, dependency, service or permission changes. The v0.26.1 case-report
  fix remains included; no evidence recreation or test rerun is required.
- The v0.9.0 minimum direct-upgrade boundary and existing
  [upgrade/recovery exceptions](upgrade-recovery.md) remain unchanged.
- Upgrade Mainframe and Agents together for Fabric jobs. Drain or cancel those
  jobs before rollback to workers that do not understand Fabric targets.
  Loop Inspector remains experimental; no new appliance acceptance is claimed.
- User explicitly requested stable v0.26.2. Future beta builds still require
  explicit prerelease versions and matching tags after updater support; see
  [beta release policy](beta-releases.md).

## Existing feature evidence

- [x] PR #304: focused 30 tests and 344 subtests; full 2,416 tests and 481 subtests;
  all six PR CI jobs passed. Regression coverage includes all pages, errors,
  quoting/Unicode/formula text, null latency, unavailable runs and access controls.
- [x] Synthetic comparison/load browser checks at desktop/mobile widths across
  six palettes, keyboard downloads, no overflow or JavaScript errors.
- [x] Local normal restart after idle checks and health verification passed.
  This is not a claim of new physical Agent/fleet acceptance.

## Release candidate

- [ ] Full suite in a fresh environment with hash-locked development dependencies.
- [x] Dependency provenance, shell syntax, bundle/checksum/source verification,
  private/runtime exclusions and compatibility from v0.26.1.
- [ ] Reviewed preparation PR and all six candidate CI jobs passed.
- [ ] Merged-main CI passed and source equals the reviewed candidate.

## Publication

- [ ] Annotated v0.26.2 tag on verified main, matching APP_VERSION.
- [ ] All tag CI passed before publication.
- [ ] Release and upgrade-bundle workflow completed with ZIP and SHA256 assets.
- [ ] Published assets downloaded and verified against tagged source; stable
  discovery from v0.26.1 offers v0.26.2.

Follow [the release process](../CONTRIBUTING.md#releases). Do not move a published
tag or pre-check future gates; record final evidence in the release/private record.
