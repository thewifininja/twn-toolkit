# Automation prerequisites and retained draft

Scope: first automation → create missing reusable condition/schedule/action → return to the same builder → save paused → inspect saved card/history. No engine, scheduler, execution, arming, trust policy or credential lifecycle changes.

## Source finding and change

The initial builder defaulted to condition mode, but empty condition/schedule lists only said to create a definition elsewhere; with no saved actions it omitted the stage editor and disabled Save. Leaving to create prerequisites discarded the unsubmitted builder. Existing library forms and validators already supported the necessary definitions.

The builder now opens create-only dialogs using those same editor macros and existing admin-guarded save routes. An explicitly requested JSON response contains only the new reference (kind/id/name/type). The selected condition, schedule, or stage action is inserted into the original parent draft; stage names, order, delays, mode and other values remain in page memory. Native fallback links open the existing library in another tab; Refresh saved choices updates references without leaving the parent. Missing saved references remain visible for explicit removal. Reusable items are not run by saving them; the final button explicitly saves the automation paused.

Back/Escape retains the child draft in the current page. Pending saves prevent closing and repeated submission. Validation and uncertain network responses retain both drafts and never retry a POST automatically. A successful save clears password fields and write-only webhook headers; no browser storage or draft endpoint is introduced. Leaving a page with abandoned child edits uses the existing unsaved editor warning.

## Evidence ledger

| Scenario | Evidence/status |
| --- | --- |
| Initial missing definitions | Source inspected: builder macros and prior stage omission; existing page/backend tests passed. Parent CUA verified the first-use path on the isolated fixture. |
| Create all three definition types | New synthetic Flask tests: minimal 201 response; no automation/runs created; duplicate names and attempted edit IDs rejected. |
| Complete parent composition | Synthetic Flask test: condition and two action references retained in requested order, automation saved disabled, no run history, returned page HTTP200. |
| Refresh references | Backend projection test: no config getter access; only id/name/type; built-in manual trigger excluded. Client preserves unavailable selections instead of silently clearing them. Parent CUA verified successful created-choice selection; stale/error branches pending. |
| Permissions/native/agent-prefix | New tests: anonymous redirects to login, nonadmin 403; response mode requires both explicit flags, native library saves retain redirect behavior; prefixed URLs rendered correctly. |
| Back/Escape and narrow layout | Parent CUA: all three child editors retained values after Back/Escape and reopen; parent name and selected action survived creating the schedule. At 600×850 the dialog footer remained within the viewport and no horizontal overflow was observed. |
| Save paused and return | Parent CUA: saved calendar/action card focused after redirect, paused and no occurrences/runs; Arm/test/run never clicked. Paused card wording corrected and covered by backend tests. |
| Pending/repeated submission | Parent CUA: 8-second synthetic save with double click admitted one POST; controls/Back disabled and Escape kept the dialog open until acknowledgment. |
| Uncertain acknowledgment and refresh | Parent CUA: server saved a synthetic condition but returned HTML; both drafts remained and explicit refresh recovered the new unchecked reference. POST count remained two across both probes; no automatic replay. |
| Secret clearing | Parent CUA: confirmed synthetic webhook definition save cleared both inactive SSH password inputs and write-only headers; TLS verification remained selected. No webhook request was sent. |
| Validation error and removed references | Parent CUA: synthetic 400 retained action name and write-only headers; removing only a disposable fixture action then refreshing retained an explicit unavailable selection, disabled Save paused and kept parent name/conditions. |
| Return/history | Parent CUA: saved paused calendar → empty check/run history → Back to same focused card. Paused wording and arm-to-schedule explanation observed; Arm never clicked. |
| Repeat-use empty selection | Parent CUA caught a blank default ID shown as a phantom unavailable condition on a new builder with populated libraries. Fixed blank normalization and excluded built-in non-condition trigger IDs; empty/populated and saved-calendar regression tests added. Parent CUA fresh populated-library GET verified three available unchecked conditions, zero checked/empty IDs, and no unavailable placeholder. |
| Timeout | Parent CUA: 18-second fixture delay hit the 15-second client bound, retained parent/child values, re-enabled controls, explicitly directed refresh before retry. Five explicit attempts produced exactly five counted POSTs; no automatic replay. |
| Real automation execution or delivery | Intentionally excluded; no arm/test/run, host commands, SMTP/webhook delivery, production data or live settings touched. |

## Isolated browser fixture

`tests/fixtures/automation_prerequisites_app.py` starts a fresh temporary standalone instance on loopback only, without an engine, scheduler, workers or agents. Routes are allowlisted for composition saves and read-only navigation; arm/test/run are rejected. Outbound `socket.create_connection` is denied. No production instance or secrets are loaded. The fixture is intended for supported browser checks; its POSTs save only synthetic definitions and paused automation records.

Checks: 15 focused tests passed after the browser-discovered blank-selection fix. The final wider affected automation/registry check result is recorded in the task handoff. Both changed JavaScript files passed V8 syntax compilation. No Node runtime is installed here. Root CUA checked the actual isolated browser branches recorded above. Required full aggregate and final independent exact-head review remain release/deployment gates; no live deployment is performed by this branch. Root owns independent review, integrated aggregate checks and deployment.
