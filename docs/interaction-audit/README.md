# Interaction audit — 2026-10-31

Scope: Toolkit user interactions, preserving the established visual character.
This is an ongoing coverage ledger, not an exhaustive usability sign-off.

## Inventory and evidence

`inventory.csv` indexes declared routes, template controls/dialogs/disclosures and
literal client event handlers. Regenerate with `python scripts/inventory_interactions.py`.
It parses source only, does not import the app or read instance data. Each row
starts unverified; the batch ledger below supplies behavioral evidence. Dynamic
route registration, generated controls, macro expansion, delegated Agent pages,
keyboard handlers registered indirectly, and conditional combinations require
runtime follow-up. Line numbers are navigation hints, not stable identifiers.

Status vocabulary: **observed** = read-only live page/screenshot; **tested** =
asserted against isolated synthetic state; **inferred** = source reviewed;
**unverified** = no behavioral evidence yet. A route being listed is not tested.

## Batch ledger

| Flow | Current evidence | Next validation / remaining gap |
|---|---|---|
| Dashboard → search / target / favorites | Observed signed-in local dashboard; `internet` no match, `dns` matches; target only This instance | Novice aliases, unavailable-agent explanation, result continuation links; nonadmin and empty account unverified |
| Bulk SSH hosts → commands → review | Observed original empty state; source-reviewed draft/preview safety; batch changes compact header and add explicit Save & continue | Tested save/validation/no-execution in `test_bulk_ssh_workflow`; full draft/back/reload browser matrix remains unverified |
| Remote Terminal → Quick connect | Observed SSH/22 defaults, optional title, one-time credentials, cancel; no connection attempted | Mock connect/error/retry/reconnect, SSH/Telnet/console differences |
| Remote Terminal → New/Edit host | Observed original New dialog; batch groups destination/credentials/organization and keeps footer available | Isolated New/Edit, validation inside disclosures, keyboard/footer at narrow/short viewports and all palettes |
| Loop Inspector host selection | Inferred page-one-only truncation; batch uses complete permission-filtered library | Tested >100 mixed hosts, foreign private exclusion and visible shared inclusion (`test_ssh_selector_covers_complete_visible_library`); no device calls |
| Investigations list / closed journal / evidence | Observed existing list and closed case; batch prioritizes case list and selected tab content over team/merge | Synthetic empty/open/closed/collaborator cases and merge permissions; report/export unchanged |
| Bulk SSH terminal outcome | Observed historical incomplete badge with succeeded summary; source shows worker completion distinct from host success | Tested success/error completion consistent across case/activity summary (`test_terminal_summary_and_case_agree_on_host_outcome`); no historical rewrite |
| Agent lifecycle | Inferred 30-day client cert without renewal, generic disconnected state, reset/re-pair recovery | Separate design below; live security unchanged, expired-agent reproduction unverified |
| Other inventory surfaces | Unverified beyond existing repository test coverage | Audit in batches below; do not infer usability from unit-test pass |

## Coverage protocol for every flow

Record route/template/handler, role, execution instance and fixture identifier.
Exercise first use, empty/populated state, validation failure, loading, success,
actionable failure, cancellation, back, refresh, retry and double submit. Check
unsaved drafts/result return, owner/collaborator/admin restrictions, offline and
incompatible execution targets. Mark unsupported states not applicable with a
reason. Retain assertion names and screenshots for material visual changes.

Next batches: (1) shared navigation, search and saved libraries; (2) diagnostic
forms/results/history/export; (3) Fortinet profile/preview/apply workflows;
(4) automations and long-running jobs; (5) local file services/imports/transfers;
(6) administration, enrollment, updates/recovery. Each gets a separate bounded PR.

## Isolation before stateful checks

Use this worktree and a newly created `/tmp` instance, never the live instance or
its backups. Install hash-locked dev dependencies into `/tmp/twn-qol-venv`.
Generate fixture-only keys/users locally; no copying configuration or secrets.
Use Flask test clients for writes and monkeypatch execution/queue boundaries.
`create_app(instance_path=...)` constructs stores; do not invoke `twn`, worker
entrypoints, service managers or production schedulers. Synthetic worker tests
claim only their temporary DB and mock network execution. If a browser fixture
server is needed, bind loopback on a distinct port, standalone role, no enabled
automations or enrolled agents, and explicit mocked execution. Verify those
conditions before browser interaction. No production restarts or trust changes.

## Separate certificate lifecycle design (not implemented)

1. Expose parsed leaf expiry, CA trust and connection cause separately from file
   existence. Distinguish expiring, expired, revoked, untrusted and unreachable.
2. Renew while valid through existing mTLS, checking current approved identity and
   public key. Use a renewal window with jitter/backoff, bounded issuance and audit.
   Validate returned chain/identity before atomic replacement; serialize writes.
3. Expired recovery must not accept an expired leaf on ordinary work endpoints.
   A dedicated recovery exchange uses a fresh short-lived, single-use challenge,
   signed by the retained identity and bound to identity, Mainframe, purpose and
   transcript. Server consults current approved/nonrevoked record; client verifies
   its pinned Mainframe trust. Rate-limit and audit; never trust address alone.
   Removed/revoked/key-changed/lost-trust identities require administrator pairing.
   Decide explicit recovery policy and threat model before implementing access.
4. Preserve device ID, permissions, history and job fencing. Never replay expired
   jobs as a consequence of recovery. CA replacement needs deliberate trust flow.
5. Listener certificate rotation must replace the serving TLS context safely,
   not merely update disk files or a status-page display.

Isolated tests: near expiry; continuously online; offline past expiry; skew;
revoked/removed/key changed; challenge replay/parallel recovery; interrupted
replacement/concurrent readers; wrong CA/hostname; unavailable Mainframe;
listener served/disk mismatch; renewal flood/backoff; permissions/history retained;
old jobs fenced/no replay. First reproduce the reported incident independently;
its exact root cause remains unknown.

## First batch validation record

Branch: `codex/workflow-qol`, based on v0.27.0 commit `3ddaaee`.
No application version change, production restart or deployment.

- Initial focused regressions: 114 passed in 62.57 seconds. Added behavioral
  tests cover save-and-continue with no execution/preview, validation preserving
  inputs, >100 mixed-protocol host visibility and shared/private permissions,
  and success/failure summaries matching case outcomes.
- Browser fixture: `/tmp/twn-qol-ui-*`, loopback port 5097; fresh synthetic
  standalone instance, no workers/scheduler or enrolled agents, outbound
  `socket.create_connection` refused and consequential POSTs blocked. Cosmetic
  palette/density/text-scale overrides exist only in the temporary fixture script.
- New-host dialog: 96 combinations passed overflow/footer checks (390×844 and
  1280×800, six palettes, two densities, 90/100/110/125% text). Observed primary
  Save contrast ranges 5.46:1–6.66:1. Short 390×600 at 125% additionally verified
  required-name validation focuses the field, disclosure reveals organization,
  Escape cancels, and existing-host Edit retains destination/credential mode.
- Isolated browser save-and-continue creates only a synthetic matrix and opens
  commands; no job admission. Closed-case journal now precedes collapsed team
  and merge controls. Live instance was used only for earlier read-only review.
- Dependency lock provenance, `pip check`, Python compilation, shell syntax,
  whitespace and release-bundle construction passed. Bundle is validation only;
  nothing released. Final full-suite and exact-head CI results must be recorded in the PR before merge.

Remaining visual gaps: exhaustive hover/focus combinations, every Edit dialog
palette permutation, multi-user live fleet transitions, every tool/result screen,
and a complete dynamic state/action crawl. The static index does not close these.
Historical incomplete/succeeded records are not rewritten. New terminal summary
wording distinguishes worker completion from host command success; retained job
state remains unchanged.

Inventory snapshot: 364 decorated routes, 51 literal navigation registrations,
91 templates, 224 forms, 11 dialogs, 180 disclosures, 546 buttons, 797 inputs,
180 selects, 65 textareas, 220 link declarations and 533 literal event handlers.
These overlap and include conditional/shared markup; they are not counts of
unique runtime user journeys.

Certificate follow-up also needs enrollment-generation fencing: compare the
certificate's issuance generation/serial against durable authorization state.
Current normal request authorization checks approved agent ID plus public key
(`distributed_transport._approved_certificate_agent`); certificate issuance uses
random serials. Before promising that removed/re-enrolled identities can never
reuse an older certificate, test revoke → remove → re-enroll with the same key.
Retain revocation tombstones or an enrollment epoch as required. An old challenge
must not become usable after an administrator changes approval state. Keep
server CA/hostname/time validation strict during recovery; simultaneous listener
expiry must be repaired through listener rotation or deliberate administrator
trust recovery, not a verification bypass.

## Public Mainframe deployment acceptance (source facts, not configured)

- `twn` defaults browser listener to 5050; `distributed_agents.DEFAULT_AGENT_PORT`
  is 5051. `docs/distributed-agents.md` describes a separate mTLS listener,
  outbound Agent long polls, no inbound Agent callback port, explicit advertised
  certificate names and raw TCP forwarding. Preserve the Agent listener's
  end-to-end TLS and peer certificate identity; ordinary web TLS termination
  cannot substitute for its client certificate validation.
- `static/remote-terminal.js:openStream` uses the page host and chooses wss for
  an HTTPS page. Preserve Host and Upgrade through the web proxy. Origin checks
  in `app._is_cross_origin_mutation` and `agent_terminal_stream` compare scheme,
  hostname and port. A proxy scheme mismatch can break terminal upgrades.
- `app.create_app` sets Secure-cookie behavior from `TWN_TOOLKIT_HTTPS`; `twn`
  exports/unsets that according to backend TLS mode. Do not assume external
  HTTPS alone sets Secure cookies when the backend is HTTP.
- No app-level ProxyFix or explicit forwarded-header trust configuration was
  found. The pinned Gunicorn does have its own secure-scheme/trusted-forwarder
  settings; actual launcher/proxy behavior needs isolated acceptance testing.
- Login throttling uses WSGI `request.remote_addr`, not arbitrary forwarded
  headers (`docs/login-throttling.md`). A proxy may group clients into one source
  bucket; any address middleware must trust only the configured proxy.

Multiple web backends behind separate subdomains on 443 plus a dedicated
public TCP port for Toolkit mTLS fit the listener separation. This does
not establish deployment readiness: validate public origins/cookies, forwarding
trust, session expiry, WebSocket/streaming timeouts, mTLS enrollment/renewal,
resource isolation and backups in a dedicated environment first. No other application
configuration or current live settings were inspected or modified in this batch.

Validation history: the first full run had 2,447 passes, 481 passing subtests and
one obsolete header-label assertion failure in `test_ssh_commandlets`. Its header
and numbered-tab expectations were updated for the intentional UI changes; the
preview/execution assertions remain. Final full run completed: **2,449 passed, 481 subtests passed in 685.28 seconds**
(`/tmp/twn-qol-full-final.log`). No PR/CI result exists yet; remote review remains
a separate merge gate. Additional continuation/MSO focused run: 19 passed.

Additional isolated visual evidence: 12 New-host variants at 390×600, 125% text,
six palettes and both densities, with sharing controls rendered by the fixture,
passed overflow/Save-visibility checks (108 targeted dialog combinations total).
No Mainframe role, enrollment, worker or sharing state was enabled. The fixture
server and tabs were closed and the viewport restored. The live checkout remains
on `main` at `3ddaaee` with its existing untracked manifest preserved.

Public listener clarification: `distributed_terminal._connect_mainframe` opens
an outbound mTLS connection to the same Agent listener and uses the private
`twn-terminal-v1` upgrade. It adds no public port. Agent Mainframe URLs must be
HTTPS and cannot carry a path prefix (`_normalize_agent_mainframe_url`).
