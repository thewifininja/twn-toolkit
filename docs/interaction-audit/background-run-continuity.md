# Background diagnostic continuity

Scope: return to an owned background diagnostic, edit settings for a future run,
then keep those settings when the old run finishes or is cancelled. This batch
changes no device execution, job admission, credentials, persistent trust or
operational limits. Bulk Transfer's separate per-file outcome-label mismatch is
not addressed here.

## Before and after

Before, the shared poller reloaded the current page on completion. Only the
iPerf client supplied the optional dirty-form binding, and even that protection
required discarding new settings to view the old result. A normal Cancel form
also navigated away. Recent diagnostic history selected only the newest ten
jobs, so an older running job could disappear beneath newer finished jobs.

Now editable diagnostic pages opt into the existing in-memory unsaved-form
guard. Completion with a clean page still performs a read-only refresh. If any
tracked editor is dirty or pending, the page keeps it, updates the old run's
terminal state and offers its server-bound retained result in a new tab. The
link uses the original run identity and Agent prefix; it does not submit the
new form. A missing guard on an opted-in page fails closed by retaining settings.
No draft or credentials are added to browser storage.

An unchanged valid native POST also needs protection: its server response can
still be pending when the previous run finishes. The poller tracks same-tab
native submission intent synchronously, without copying fields or preventing
the original submission. After all handlers/unsaved guards run, a cancelled
`submit` event clears that intent in a deferred post-dispatch check. The
protection also checks the event’s final cancellation flag directly. `pageshow` clears stale native
intent on history restoration without resetting editor baselines. Async prevented
submissions, dialog forms and new-tab forms do not set the fence. Direct legacy
`form.submit()` bypasses native `submit` observers; current inspected diagnostic
entry paths use normal submit controls, and this batch does not claim coverage
for future code invoking that bypass.

Shared-panel cancellation is a single explicit POST of the cancel form, followed
by status GETs. It does not serialize the primary settings form or navigate away
from a new draft. Duplicate clicks while cancellation is pending are ignored.
Uncertain or denied cancellation remains visible; POSTs are never retried
automatically. The existing server ownership/permission checks remain authoritative.

Network polling failures retry GETs safely. Authentication/access/missing/expired
results pause polling and offer an explicit Retry status action. Returning via
browser history resumes status observation; a response arriving after pagehide
cannot reload the departed page. Terminal controls stop polling and disable
cancellation. An unconfirmed outcome remains labelled unconfirmed.

Owned active diagnostic jobs are projected separately from ten recent terminal
jobs. Active and terminal rows come from one SQL statement/snapshot, so a worker
completion cannot produce contradictory duplicate rows between two queries.
The active projection is capped at the validated per-user maximum of 200,
selects only id/state/created and does not decrypt configurations in this raw
store projection. Adapters such as Bulk SSH still load/decrypt authorized rows
to obtain their display names; maximum-load page performance is unverified.
The existing scoped history disclosure shows active work first, with newest
active runs first, exposes an in-progress count and distinguishes View progress
from View result. This is a bounded continuation index, not a new
unbounded all-history query or a new permission surface.

## All shared script consumers inspected

There are **17** `diagnostic-job.js` template consumers: sixteen use the shared
panel; Certificate request has a custom panel.

| Consumer | Concurrent settings | Handling in this batch |
|---|---|---|
| DNS Tester | `dns-form` | Opted into unsaved guard; scoped result/progress link and async cancellation |
| TCP Port Scanner | `port-scan-form` | Same; retained result filtering remains server-owned |
| Bulk Transfer | `bulk-transfer-form` | Same; no change to partial-publication or retry semantics |
| iPerf3 | Client form plus optional new-server form | Existing client protection retained; server draft now tracked too |
| DHCP inventory | `dhcp-discovery-form` | Discovery form tracked; retained snapshot filters remain unchanged |
| Switch loop inspector | `loop-scan-form` | New scan settings tracked |
| Wireless client history | `wireless-history-form` | Profile/Fabric/MAC/time/VDOM draft tracked |
| FAC MAC Devices | `fac-devices-form` | Fetch/export choices tracked |
| FAC Group Memberships | `fac-memberships-form` | Fetch/export choices tracked |
| FAC MAC Cleanup | `fac-cleanup-form` | New preview settings tracked; apply/identity safeguards unchanged |
| Appliance read job | No concurrent new settings form | Clean completion keeps read-only refresh; shared progress/cancel links |
| Rename job | No concurrent new settings form | Same; no replay or mutation semantics changed |
| Switch order job | No concurrent new settings form | Same; reviewed order/apply boundary unchanged |
| FAC cleanup job | No concurrent new settings form | Same; destructive apply and uncertainty safeguards unchanged |
| Case export job | No concurrent new settings form | Same; selected case/export snapshot unchanged |
| Configuration/automation export job | No concurrent new settings form | Same; download reservations and source permissions unchanged |
| Certificate request job | Custom panel; reconciliation only after uncertainty | Existing native cancellation/reconciliation unchanged; clean-page poll refresh retained |

## Verification and exclusions

`test_diagnostic_continuity.py` exercises synthetic DNS/TCP/Transfer admission,
exact retained links with an Agent prefix, no resubmission on GET, foreign job
exclusion, cancellation, tool permission denial, bounded terminal history and
older active work. Network execution boundaries are patched to fail if reached.
The browser fixture's controlled success/error responses and retained pages are
also asserted against temporary databases.

`tests/js/diagnostic_continuity.js` is a dependency-free in-memory state/DOM model,
not a browser or layout test. It covers clean/dirty completion, fallback guard,
network retry, access denial, expiry, duplicate cancellation, uncertain cancellation,
login redirects, unconfirmed outcomes and history/pagehide races. A Python runner
uses Node when available; local Node absence is an explicit skip, with the same
model executed separately in the host JavaScript runtime. Browser keyboard,
new-tab behavior, narrow layout and visual checks remain separate evidence.

The child audit environment had no available browser surfaces. The isolated
`tests/fixtures/diagnostic_continuity_app.py` fixture was supplied to the parent
for supported CUA testing: loopback only, new temporary instance, standalone
role, no worker/scheduler/agents, outbound connections blocked, and new diagnostic
submissions rejected/counted. Its control file modifies only fixture jobs.
No real diagnostic, transfer, device mutation or live security action was tested.
Parent independent review, final exact-head aggregate and any development rollout
are separate gates; do not treat this source ledger as their completion.

Validation checkpoint: the shared-consumer affected suite on `2bd7bcd` passed
340 tests and 37 subtests, with one explicit Node-unavailable skip. After the
active-first history refinement, the focused history/continuity/UI suite on
`d9c3eaa` passed 81 tests and 37 subtests with the same Node skip. The 13-case
in-memory JavaScript model was executed separately in the host JS runtime and
passed; this does not substitute for a real browser. Backend HTTP smoke checks
returned 200 for the isolated fixture index and all three synthetic retained-job
pages. Root later reproduced the native-POST race against the recorded `bd2c18c`
baseline in the isolated browser fixture: an unchanged valid DNS submission
received a new admission/303 on the server, while old-run completion reloaded
the old result page before that acknowledgement reached the browser. The fenced client then reached the new owned-job acknowledgement after the
same delayed POST while the old run finished. This is a browser reproduction
and repair check, not device execution. Final integrated aggregate remains
pending.

Review follow-up checks add a deterministic second-connection completion during
the history read and synthetic slow native admission that finishes the old run
mid-request. The expanded 21-case in-memory model explicitly covers native
in-flight fencing, later preventDefault, history reset, network throw, timeout
and unexpected cancellation responses. Cancellation accepts only the expected
retained-result redirect as an acknowledgement; other responses stay uncertain
and status remains read-only.

Review follow-up: the affected consumer suite on `40646d0` passed 343 tests and
37 subtests with the same explicit Node skip. A final post-dispatch cancellation
check uses a zero-delay task, rather than relying on microtask ordering between
native event listeners; the model also checks the final cancellation flag and
retains a read-only result link if a briefly marked submission is later cancelled.
