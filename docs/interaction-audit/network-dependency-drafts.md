# SNMP and RADIUS dependency draft continuity

Base: efa50d7 (includes a0e0356 case authoring and the preceding failure-state batch). Focused commits ddff1a0 (public catalogues), 5dd2cdb (editor continuity), 0d2de9c (receipt/state corrections), f135656 (v3 presence binding), followed by the saved-card layout/test/evidence correction. This is bounded journey coverage, not a complete application audit.

## Observed problem and implemented path

Baseline synthetic browser checks reproduced both failures: an SNMP host draft survived saving its prerequisite credential but the new credential was absent from its selector; saving a RADIUS credential reloaded the page and reset the composed Run selections, protocol, timeout and retries. The replacement path saves in place, exposes authoritative public choices without selecting or executing them, preserves other editor/Run drafts, and provides explicit return and Create another actions. Managed duplicate uses the persisted source, not unsaved editor values. Existing local same-name save and MSO version/conflict semantics remain unchanged.

Confirmed receipts bind public metadata and secret-presence flags to the submitted snapshot before clearing unchanged submitted secrets. Newer pending edits remain dirty. Unknown acknowledgments retain drafts and offer read-only catalogue refresh without automatic retry or adopting an uncertain identity. Access errors retain text and give sign-in/access guidance. Confirmed deletion requires explicit Create another before another save. Initial catalogue reads are silent; stale refresh responses cannot overwrite a newer save. Saved cards leave the absolute-position create layout; long summaries/status wrap. The latter layout correction is source/model verified, not visually verified.

## Evidence and limits

- Backend catalogue/receipt/permission/registry and isolated response-contract tests cover all six dependency kinds, stale versions, duplicates, public redaction, blank-secret preservation and v3 presence flags. Fixture tests verify actual Flask status/MIME and committed-state telemetry rather than inferring fault modes.
- Exact shipped editor/guard/receipt host-V8 model: eight groups cover stale GETs, pending newer secret/name, operation locks, canceled MSO preparation, canonical duplicate, deleted editor, neutral checkbox insertion and dirty Create another cancellation. Pure receipt model covers eleven groups. Existing shared models cover sixty scenarios; optional Node wrappers skip when Node is absent, separately executed V8 models are the execution evidence.
- Actual 5dd browser happy paths preserved SNMP host and RADIUS CHAP/timeout/retry drafts, made new choices available unselected, and retained selections through invalid Run validation. Its five saves and two invalid runs had zero execution-boundary calls.
- Actual fresh f135 browser fault checks: normal save, clean Create another, 400 JSON, 403 HTML, same-name wrong username, read-only recovery, genuine JSON 500/HTML after committed save, and delayed double-click with newer edits. Seven explicit saves, zero invalid runs and all seven runner/socket counters zero.
- Browser evidence: baseline/core/final evidence artifacts are retained outside the repository as twn-dependency-baseline-browser-evidence.json and twn-dependency-final-browser-evidence.json. The latter separates heads and counters.
- A dirty Create another native confirmation blocked supported browser input. Click and subsequent supported dialog/close controls timed out; no dialog handle was exposed, and the tab remained open. Outcome is uncertain, not an approval denial or established product failure. No bypass was attempted. Actual final v3, duplicate, repeat-host return/focus and narrow/long-name visual checks remain unverified. Dirty Cancel is model verified only.
- No real DNS/SNMP/RADIUS requests, credentials, agents, schedulers or live instance mutations. Execution, device interoperability, large-load performance and other tools' dependency journeys remain unverified.

The additive guard control-registration API preserves existing dirty baselines. An unsupported asynchronous sequence capture → add controls → acknowledge the old snapshot can leave a false-dirty marker; current Run forms use native submissions, not that sequence. No draft loss was observed or inferred from that limit.

## Next coverage

When supported browser input is restored, verify final v3 and duplicate/repeat-host returns and narrow saved-card layout. Separately review the observed RADIUS hierarchy: the large always-visible EAP-disabled explanation competes with the PAP/CHAP task. Do not infer real protocol/Agent coverage from these fixtures.
