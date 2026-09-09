# v0.25.0 release checklist

This release consolidates the work since published v0.24.0, including development
versions v0.24.1–v0.24.5. Publication evidence is recorded in the
[GitHub release](https://github.com/thewifininja/twn-toolkit/releases/tag/v0.25.0)
after the gates below pass; unchecked publication entries describe the state of
this document when the release candidate was committed.

## Scope

- [x] Full-screen guided installer with OS detection, service-first location
  choices, searchable timezone, granular optional tools and reviewed native
  package/permission changes; existing-instance preservation and unattended upgrades.
- [x] Independent Mainframe agent selection per tab URL, retained across reloads,
  bookmarks and scoped actions; same-login tabs/devices can target different agents.
- [x] Supervised Bulk SSH, appliance/certificate work and exports with retained
  results, cancellation, bounded resources and explicit recovery outcomes.
- [x] Friendly Bulk SSH run names, themed collapsed host results and shared compact
  Recent runs near page headings; active controls remain visible separately.
- [x] Contextual library lookup, wireless-client display/export encoding fixes,
  single-packet capture statistics, and job/storage/protocol/worker hardening.
- [x] Full automation builder remains the creation/editing path; remove Guided
  Automation while preserving definitions and redirecting old setup bookmarks.
- [x] MSO synchronization is outside this release. Existing sharing and visibility
  controls do not replicate objects between instances. EAP remains disabled.

## Upgrade and compatibility

- Retain the bundle's v0.9.0 minimum direct-upgrade boundary. Installations without
  the built-in updater and older systemd updater exceptions still follow the
  documented [upgrade instructions](upgrade-recovery.md).
- Upgrade Mainframe and Agents to the same release and reload open browser pages.
  No general service reinstall is required. New optional OS tools or additional
  service permissions require explicit setup choices; ordinary upgrades do not
  silently enable them.
- Instance data, saved automations and credentials are preserved. Retained results
  remain bounded by their configured retention policy. Do not replay uncertain
  external operations without checking the target's state.
- See [guided installation](guided-installation.md),
  [agent targeting](distributed-agents.md#execution-context),
  [background transfers](background-transfers.md), and
  [recovery](upgrade-recovery.md) for operational details.

## Existing acceptance and release-owner disposition

- [x] Automated coverage and desktop/mobile Chromium checks for background history,
  host results, independent agent tabs, and full automation creation/editing.
- [x] Operator acceptance of Bulk SSH, CM5 Remote Terminal, wireless-client export,
  Cases, physical DHCP Discover, basic iPad browsing and the redesigned SSH results.
- [x] Native macOS operator report: installation starting with Homebrew and its
  Python, manual startup, conversion to service, and service-removal guidance when
  returning to manual mode. This is not a claim of every optional helper operation.
- [x] Release owner accepts proceeding without the remaining appliance/CA mutation,
  deliberate power-loss/disk-pressure recovery, extended fleet/helper soak,
  exhaustive accessibility and additional operational acceptance checks. These
  scenarios remain unperformed or only partially covered; they are waived as
  v0.25.0 release blockers, not reported as test passes or universal guarantees.

## Release-candidate validation

- [ ] Full suite in a fresh virtual environment with hash-locked dependencies.
- [ ] Dependency provenance, shell syntax, version/Help checks and exact-source
  bundle manifest/checksum verification; private and runtime content excluded.
- [ ] Review release-preparation PR and pass all six CI checks.
- [ ] Pass merged-main CI and verify exact reviewed/main tree equality.

## Publication gates

- [ ] Annotated v0.25.0 tag at the verified main commit; tag matches APP_VERSION.
- [ ] All tag CI checks pass before publishing.
- [ ] GitHub release published; release bundle workflow succeeds.
- [ ] Downloaded ZIP and checksum match; all payloads match tagged source and
  manifest; normal updater release discovery offers v0.25.0.

Follow [the release process](../CONTRIBUTING.md#releases). Record final PR, commit,
CI links, test counts and artifact checksum in the published release without
moving the tag or retroactively claiming waived checks were performed.
