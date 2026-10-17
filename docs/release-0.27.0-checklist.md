# v0.27.0 release checklist

Stable workflow release following v0.26.2, consolidating PRs #306–311.
The owner authorized moving forward with the proposed v0.27.0 release.
Post-commit evidence belongs in the GitHub release; unchecked gates are pending,
not assumed passes. Follow [the release process](../CONTRIBUTING.md#releases).

## Scope and compatibility

- [x] Bulk SSH long scripts and quoted multiline input, including FortiGate PEMs.
- [x] Bulk SSH copies from current edits, Save & add to run, action draft retention,
  run-order preservation and field/confirmation alignment.
- [x] Remote Terminal selection retention across pages/searches, review/removal,
  broader opt-in bulk edits and direct host/folder actions.
- [x] Fix expanded-list bottom-row clipping, including selection mode and short windows.
- [x] APP_VERSION, built-in release notes, README, Quick Start and version tests updated.
  Existing Help and focused workflow guides already describe the shipped features.
- [x] Regenerate both hash locks and provenance with the pinned resolver, updating
  only urllib3 2.7.0 → 2.8.0 and Werkzeug 3.1.8 → 3.1.9. Fresh audit identified
  PYSEC-2026-4175/4176/4177 and PYSEC-2026-4312; existing CI exceptions are unchanged.
  See [urllib3 advisories](https://github.com/urllib3/urllib3/security/advisories)
  and [Werkzeug changes](https://werkzeug.palletsprojects.com/en/stable/changes/#version-3-1-9).
- No new database schema, service or permission changes. The updater installs
  the updated hash-locked dependencies.
- Upgrade Mainframe and Agents to use the changes on each execution target. Save
  drafts and finish active jobs/sessions before an upgrade; reload browser pages.
  Drafts and selections are page-local. A service restart interrupts live shells.
- Previous v0.26.1 case-report fixes and v0.26.2 DNS CSV exports remain included.
- Existing minimum direct-upgrade version v0.9.0 and [recovery exceptions](upgrade-recovery.md)
  remain unchanged. Drain/cancel Fabric jobs before rolling back to older workers
  without Fabric target support. Loop Inspector remains experimental.
- Quoted multiline input is not arbitrary expect/heredoc support. Per-command
  timeout, worker deadline, cancellation, concurrency and output limits remain.
- Durable SSH host-key enrollment and further library conveniences remain separate
  backlog. No new physical appliance/fleet acceptance is claimed for this release.
- Future betas require supported prerelease versions and matching tags; see
  [beta policy](beta-releases.md). This release is stable, not a numeric beta.

## Existing feature evidence

- [x] PRs #306–311 reviewed and merged with required platform CI passing.
- [x] Historical full suite: 2,443 tests and 481 subtests passed on the final feature tree.
- [x] Historical synthetic browser coverage: Bulk SSH drafts/copies/run assembly;
  terminal cross-page selection, bulk edits, row actions, MSO rejection, all themes,
  mobile/desktop, density/text scale, and 80 expanded-list scrolling cases.
- [x] Previously recorded operator acceptance of long/multiline Bulk SSH input.
- [ ] Fresh physical-device/operator smoke test of this release candidate.
  This is supplementary acceptance, not claimed or waived by the release request.

## Release candidate

- [ ] Full suite in a fresh environment with hash-locked development dependencies.
- [x] Dependency provenance, shell syntax, bundle/checksum/source verification,
  private/runtime exclusions and upgrade compatibility from v0.26.2.
- [ ] Reviewed preparation PR and all six candidate CI jobs passed.
- [ ] Merged-main CI passed and source equals the reviewed candidate.

## Publication

- [ ] Annotated v0.27.0 tag on verified main, matching APP_VERSION.
- [ ] All tag CI passed before publication.
- [ ] Release and upgrade-bundle workflow completed with ZIP and SHA256 assets.
- [ ] Published assets downloaded and verified against tagged source; stable
  discovery from v0.26.2 offers v0.27.0.

Never move a published tag or pre-check future gates. Record final publication
and validation evidence in the release/private record.
