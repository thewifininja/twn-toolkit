# v0.26.0 release checklist

This release consolidates all changes since published v0.25.0, including the
numeric v0.25.1–v0.25.6 MSO and terminal pilots. Publication evidence belongs in the
[GitHub release](https://github.com/thewifininja/twn-toolkit/releases/tag/v0.26.0)
once the gates pass. Unchecked entries reflect the candidate's committed state.

## Scope

- [x] Bidirectional Mainframe Synced Objects with stable identities, offline
  catch-up, new-Agent bootstrap, durable deletions and central conflict review.
- [x] All 21 supported object kinds: saved network lists, SNMP/RADIUS credentials,
  LLDP personas, FortiGate/FortiAuthenticator profiles, Bulk SSH matrices/actions,
  and eligible Remote Terminal folders, hosts and credentials.
- [x] Dependency sharing and full terminal paths; private terminal objects and
  serial consoles remain local. Defaults stay local and existing objects are not
  automatically opted into sharing.
- [x] Role-aware Mainframe tabs, searchable MSO inventory, manual synchronization,
  Agent support/error/conflict status and accepted-versus-received distinctions.
- [x] Compact capability popovers, themed MSO switches and readable Save controls.
- [x] On-demand local/Agent Remote Terminal streaming with bounded resources,
  ownership/Origin/revocation checks, hidden-viewer detach and retained-output
  recovery; ordinary idle Agent polling cadence is unchanged.
- [x] Automations and Certificates/PKI remain deferred for MSO. Cases, notes,
  evidence, attachments, datastore content, SMTP and dashboard settings are excluded.

## Compatibility and operation

- Upgrade Mainframe and Agents to the same release and reload browser pages.
  Numeric v0.25.1–v0.25.6 pilots can upgrade directly to v0.26.0. The bundle retains
  the v0.9.0 format boundary; older updater/service exceptions remain documented
  in [upgrade and recovery](upgrade-recovery.md).
- Participating JSON libraries migrate once to `mso.sqlite3`; retained legacy JSON
  is no longer active. Native Remote Terminal libraries retain their identities.
  Recovery preserves code and instance data together; restoring older Mainframe
  history can require explicit reconciliation. Portable imports remain local.
- Enable MSO deliberately. Global/Admins Only terminal objects can share; private
  objects cannot. Eligible dependencies share with their references. Leaving a
  Mainframe preserves local copies; revocation does not remotely wipe an Agent.
- Browser WebSockets reach Mainframe's web port (default 5050); Agents initiate the
  terminal relay outward to its existing mTLS listener (default 5051). No direct
  Mainframe-to-Agent web-port connectivity or new Agent listener is required.
  Older peers/proxies without streaming support retain HTTP fallback.
- MSO catch-up is progressive (four objects per exchange). Conflicting offline
  edits require review. Accepted on Mainframe does not mean received by every Agent.
- See [MSO](mainframe-synced-objects.md), [terminal streaming](terminal-streaming.md)
  and the required [future beta versioning policy](beta-releases.md).

## Existing evidence and acceptance

- [x] Feature PRs and their merged-main CI passed all six checks. Latest pilot:
  2,317 Linux tests; 2,316 plus one platform skip on macOS; 472 subtests.
- [x] Automated migration, credential protection, dependency/visibility, conflict,
  offline/bootstrap, backup and concurrent ownership/delivery regressions.
- [x] Desktop/narrow Chromium checks across three roles and six palettes, keyboard
  and touch controls; HTTPS Gunicorn reconnect/replay/UTF-8/hidden-viewer checks;
  repeated real mTLS disconnects with disposable SQLite integrity checks.
- [x] Physical CM5 pilot: bidirectional tool-library synchronization and cleanup;
  production HTTPS browser/mTLS terminal relay with exact echo, UTF-8, reload
  recovery and zero idle output polls. Loopback measured 28 ms median/33 ms p95;
  this is fixture evidence, not a guarantee for arbitrary devices or links.
- [x] Operator reviewed the MSO interface and terminal work and authorized v0.26.0.
  This does not claim exhaustive physical SSH/serial device coverage, fleet-scale
  soak, network bandwidth measurement or new fault-injection acceptance.

## Release-candidate validation

- [x] Direct data migration from a disposable instance seeded by published v0.25.0:
  five representative profile libraries and three native terminal libraries retain
  values, credential access, IDs and local-only defaults; SQLite integrity passes.
- [x] Complete suite in a fresh virtual environment using hash-locked dependencies.
- [x] Dependency provenance, shell syntax, version/Help checks and exact-source
  bundle/checksum verification, excluding private/runtime content.
- [ ] Reviewed release-preparation PR and all six candidate CI checks.
- [ ] All six merged-main CI checks and exact reviewed/main tree equality.

## Publication gates

- [ ] Annotated v0.26.0 tag on the verified main commit, matching APP_VERSION.
- [ ] All tag CI checks passed before publication.
- [ ] GitHub release published and Release upgrade bundle workflow succeeded.
- [ ] Published ZIP/checksum downloaded and verified against the tagged source;
  normal stable release discovery offers v0.26.0.

Follow [the documented process](../CONTRIBUTING.md#releases). Record post-commit
validation and publication evidence in the release; never move the published tag
or pre-check future gates. No prerelease parser or discovery behavior changes are
included here: those must precede the next tagged beta deployment.
