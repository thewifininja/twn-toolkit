# Application interaction pass — current scope and coverage

Baseline inspected: `84077b4`. This ledger is a task inventory and a source review,
not an assertion that the entire application is user-friendly or runtime tested.
No live routes were requested, devices contacted, jobs started, settings changed,
or production instance files read for this reconciliation.

## Inventory reconciliation

The source-only `python3 scripts/inventory_interactions.py` finds **364 route
handler declarations, 51 ToolLink navigation declarations and 94 templates**.
The earlier ledger had 91 templates; the three additions are Bulk SSH's
`_multi_ssh_composer.html`, `_multi_ssh_connection_choices.html` and
`_multi_ssh_review.html`. Route and navigation declaration counts are unchanged.
The current literal index also has 224 forms, 551 buttons, 807 inputs, 220 links,
180 selects, 68 textareas, 185 disclosures, 11 dialogs and 543 event-listener
occurrences. These are index counts, not interaction coverage percentages.

Route decorators can share endpoints and route arguments; app factories,
blueprints, endpoint aliases and dynamic registration affect the runtime map.
The HTML scan does not expand Jinja macros/includes/conditionals and its tag
regex is not an HTML parser. Generated controls and event delegation can produce
many runtime interactions from one literal occurrence. Conversely, a literal
control can be hidden, unavailable or unreachable in a given role. Do not use
these counts as a denominator for a claim of exhaustive behavioral coverage.

[`journeys.csv`](journeys.csv) gives each of the 51 declared navigation items a
complete user task, evidence status, source/template reference, role matrix,
execution-context matrix, required state/continuity/accessibility probes and
specific next probe. Every item is indexed; most behavior remains **unverified**.
A source declaration is labelled inspected, not observed. Existing test modules
listed below are useful starting points, not tests rerun by this audit.

## Shared and non-navigation journeys

These surfaces must be audited in addition to the 51 navigation items.

| Journey | Source inspected or starting point | Required cases; current behavioral status |
|---|---|---|
| First setup → sign in → allowed starting task | `templates/auth/setup.html`, `login.html`, `auth.py` | First administrator, invalid/duplicate setup, login error, no tool grants, session expiry, safe return destination; unverified |
| Dashboard → search/favorite/category → tool | `templates/home.html`, `base.html`, `tool_catalog.py` | Empty favorites, novice synonyms, no matches, keyboard search, denied links, narrow sidebar; prior sample observations only |
| Choose local versus Agent execution context | `templates/base.html`, distributed routing | Local/member/admin; offline, revoked, incompatible, expired and unavailable target; retain intended task and explicit vantage point; unverified |
| Saved profile → edit/save/copy/rename/delete → run | Shared profile macro/client helpers | Unsaved versus stored values, overwrite/name conflict, referenced profiles, cancel/back, secrets and MSO conflict; unverified outside bounded prior batches |
| Background admission → leave → return → cancel/result/download | `components/recent_runs.html`, `diagnostic_job.html`, `static/diagnostic-job.js` | Owner versus foreign run, active/terminal/expired job, polling failure, draft edits, no replay after uncertain admission; source-inspected, parent implementation track |
| Foreground results → edit settings → rerun/export | `components/ui.html`, `static/tool-results-workspace.js` | Keep settings/result identity clear; failure/partial/empty, double submit, focus/scroll and download completeness; unverified |
| Retained exports and download reservations | `templates/exports/`, export/diagnostic route modules | Queued export, permissions revoked, expiry, cancellation, range/retry, useful empty output; existing tests only, not rerun here |
| Investigations journal → evidence → report/merge | `templates/investigations/` | Open/closed, owner/member, notes draft, attachments, case selection continuity, export cancellation, merge conflicts; bounded historical sample only |
| Live monitoring/popout → close/reopen/reconnect | Ping/terminal popout templates, live session routes | Main window lost, browser refresh, server restart, session ownership, detached view, stop versus dismiss; unverified |
| Import/CSV/upload → correction/preview → save/apply | `task.html`, datastore, Bulk SSH, profile import forms | Invalid encoding/columns/rows, duplicates, empty import, partial acceptance, no accidental save/execute; unverified outside bounded Bulk SSH tests |
| Long-lived services → bind failure → stop/restart → history | File Transfers, iPerf, syslog, capture and LLDP | Missing privileges/interface, ports occupied, service stopped/error, large histories, no unintended transmission; unverified |
| Account/access/backup/update lifecycle | Settings/backup/update templates/routes | Admin versus member; password/access/trust changes require explicit action-time approval; fixture-only stateful checks; unverified |
| Help/deep links/browser history | `templates/help.html`, route redirects, sidebar links | Stable bookmarks, retired routes, access denied, missing/expired result, back/forward retaining drafts; unverified |

## Current source-backed priorities

### 1. Return to unfinished background work without losing a new draft

The shared history adapter is collapsed initially, labels every continuation
`View`, and presents one chronological list (`components/recent_runs.html`). It
keeps active progress/cancel outside history, which is good: the existing
`test_recent_runs.py::test_collapsing_history_cannot_hide_progress_or_cancel`
asserts that separation. A useful next batch should make active continuation
obvious while preserving owner/tool/Agent scoping and result identity.

More importantly, `static/diagnostic-job.js` reloads a page when its job becomes
terminal unless `data-diagnostic-draft-form` resolves to a dirty tracked form.
Only `tools/iperf3.html` supplies `diagnostic_draft_form` in this baseline.
Bulk Transfer, TCP scan and DNS use the shared poller without that declaration.
Their editable settings therefore need explicit synthetic completion/refresh
checks before claiming drafts survive. This is a source-backed risk; browser
reproduction is not claimed here. Parent owns this implementation batch.

Required tests: edit new settings while the old job is running; finish/cancel/
fail it; polling error and reconnect; keep the new draft and original result
link; permission denial and job expiry; return from another page; repeated
admission must recover the same job rather than replay work.

### 2. Bulk Transfer: destination → queue → partial recovery

`tools/multi_sftp.html` renders **Ready to fetch** before validation and uses
**Transfer complete** whenever `results is not none`. The route exposes rows when the job state is `succeeded`
(`sftp_routes.py`), while `transfer_diagnostic.py` finishes processing in that
state even for mixed per-file errors. Its audit/case classifier separately
reports `incomplete` or `failed` from the confirmed-success count. The same
template warns that individual files can already be published when a run stops
or becomes unconfirmed. Those facts deserve one coherent outcome and recovery model: show
what was requested, what was confirmed published, what is unconfirmed, what a
retry will request, and where to find/download output. Verify route and worker
semantics before replacing labels; do not equate finished processing with all
files successfully fetched.

Starting tests: `test_transfer_jobs.py` (especially cancellation during datastore
publication, ownership and no replay), `test_transfer_admission.py`,
`test_transfer_storage.py`, `test_transfer_limits.py`. Add UI/state tests with
mock fetches and temporary datastore only; no real file services or hosts.

### 3. First automation: prerequisites → pipeline → test → arm → history

In `automations/index.html`, default condition mode has the empty message
**Create a condition before using condition mode**; schedule mode similarly
requires a schedule. Those messages themselves provide no direct creation link
or return-to-draft action. The builder also uses separately saved actions.
This suggests a bounded first-use journey audit rather than a new parallel
wizard: create the necessary reusable component, return to the partially built
automation, test observations without confusing them with response execution,
and make **Run now**, **Arm**, **Pause** and history distinguishable.

Starting tests: `test_automation_builder_entry.py` intentionally retires the old
wizard in favor of the full builder; preserve that single editing path.
`test_automation.py`, `test_automation_execution.py`, `test_automation_heartbeat.py`
and history-bound tests cover important backend behavior but are not a first-use
browser assessment. Only mock conditions/responses and disabled fixture schedules
are permitted for this batch; never arm the real scheduler as an audit probe.

## Batch boundaries and current evidence

- **Bulk SSH through `84077b4`:** prior bounded implementation/review/test evidence
  covers literal Hosts → Commands → Review & run, mixed saved/typed ordering,
  draft/stale-review boundaries, explicit per-host key/legacy choices and compact
  disclosures. Reported exact-head aggregate: 2,480 tests and 481 subtests passed.
  Those results were supplied by the implementation track, not rerun here.
  Review was source-based independently; desktop/narrow/long-content browser
  observations came from the implementation track. Real device execution was
  excluded. See the Bulk SSH batch documents; this does not cover other tools.
- **Remote Terminal:** a separate implementation worker owns the complete
  connect/error/retry/return task. This ledger does not pre-label its work fixed
  or tested.
- **Agent certificate lifecycle:** a separate worker is verifying issuance,
  renewal, listener context and expired/revoked recovery semantics. Historic
  expiry notes in the original README are hypotheses to reconcile with that
  review. Actual persistent access/trust or production credential changes remain
  a separate action-time approval boundary.
- **Other navigation entries:** indexed with precise next probes; no new runtime
  pass claimed. Source findings above are recommendations until independently
  reproduced and fixed in bounded batches.

## Execution and evidence rules

For each batch use a fresh temporary instance and synthetic users/profiles/jobs.
Do not copy live configuration, certificates, credential stores or job databases.
Do not launch schedulers, enroll agents or dispatch device work from a UI fixture.
Mock network boundaries or use explicitly local fixtures. A GET is not presumed
safe: `/mainframe` has local enrollment/TLS preparation behavior and must not be
used as a crawler target on the live app.

Record exact source revision, fixture, role, execution node, scenario, assertion/
screenshot evidence and remaining exclusions. Mark statuses independently:
**inspected** (source), **observed** (actual screen), **fixed** (candidate commit),
**tested** (named checks), **unverified** (missing behavioral evidence). A fixed
source issue is not a tested workflow, and an aggregate backend pass is not an
exhaustive UI sign-off. Preserve the existing visual language and advanced paths;
prefer complete task batches over isolated label or spacing churn.
