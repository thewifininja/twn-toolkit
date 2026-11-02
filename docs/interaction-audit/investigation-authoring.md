# Investigation authoring and saved-report handoff

Base: `88c7c7d`. Scope: case title/context → journal and shell quick note → confirmed journal entry → saved report choices/export boundary. Existing ownership, collaboration, one-open-case, recording/pause/close/reopen, report scope validation and export worker semantics are unchanged. No autosave, browser storage, POST retry or note-text deduplication is introduced.

## Reproduced problems and resulting flow

- An invalid case creation redirected to a blank form. Inline HTTP400 now retains title/context and the accessible current-case context, without listing foreign cases. Create fields use the existing unsaved guard.
- Note validation redirected and lost submitted text. Native HTTP400 retains the note; when the original case has closed, the accessible journal shows it read-only for copying. Native safe-next redirects remain compatible on successful saves. With JavaScript disabled, quick-note success still follows the native navigation fallback; underlying tool-draft continuity is not claimed there.
- The shell quick-note form promised to stay on the tool but actually posted/navigated, losing its unfinished fields. Both note surfaces now share an explicit acknowledged save, with pending lock, preserved errors/uncertainty and a bounded escaped canonical-note confirmation/link. The visible journal is not silently refreshed or appended; a note for active case A cannot be appended to viewed case B. Close/Escape preserves the current-page draft and cannot dismiss a pending save.
- An anchor into the newest journal page aged out after more than one page of later events. The existing permission-scoped pagination accepts one exclusive `include_event` cursor, fetches a bounded window including that exact event, and checks for newer entries with a bounded existence query. Acknowledgments bind origin, case path, exact event query/hash and the submitted canonical text. Comparison alone normalizes browser multipart line endings; stored note text remains unchanged.
- Report download names did not distinguish unsaved choices from the persisted selection. PDF/package links explicitly use SAVED report choices, open a new tab to keep the draft, and a dirty-selection status exposes the existing Save action. The complete portable-case export remains distinct. Print is labelled as the saved report preview. No export snapshot/job behavior changed.

## Shared guard integration

Some tool pages load the guard before the shell note dialog is parsed; others had no guard. A bounded idempotent `register(form)` API lets the later shell load register only newly parsed opt-in forms. It never replaces the singleton, resets existing dirty/pending baselines, or duplicates navigation listeners. All prior version-only guard script references now use the code fingerprint to prevent an older cached API winning. No broad form auto-registration or automatic baseline reset was added.

## Evidence and limits

| Scenario | Evidence |
| --- | --- |
| Invalid case creation | Root actual baseline/candidate browser: whitespace title plus meaningful context cleared after old redirect; new HTTP400 retained both. HTMLParser regression verifies the main element and script placement. |
| Quick note and tool draft | Root actual baseline API Tester lost URL/body after successful note; new fixture retained both, cleared only the acknowledged note, and displayed `<script>` as escaped text with no inserted script. |
| Mixed active/viewed cases | Root actual browser: closed viewed B retained its heading/timeline while the quick-note confirmation belonged to shared active A. Backend ACL/cross-case tests verify independent event stores. |
| Stable saved-note handoff | Isolated regression first failed after page-size+1 later notes. Root actual fixture injected 51 later notes before acknowledgment; `include_event` link still showed the original multiline note in three bounded rows despite 54 total case events, with Newer navigation. |
| Unicode/multipart | Root actual U+0085/multiline note acknowledged; shipped-client model covers Python strip whitespace, preserved BOM, LF/CRLF comparison and valid UTF16/CRLF expansion without changing stored text. |
| Uncertain committed write | Root actual JSON500-after-write and wrong-summary 201 retained note plus API URL/body, showed Check journal and no confirmation; opening the journal recovered the committed note. Model covers HTML, network, timeout, wrong case/origin/summary/event query and no automatic replay. Further pending/timeout browser cases pending. |
| Permissions | New isolated tests cover owner, collaborator attribution, foreign/revoked access and closed case; no rehome/reopen is performed. Root actual revoked-before-submit 404 retained the note. Improved known401/403/404 recovery copy is model verified; closed-case browser probe pending. |
| Report boundary | Root actual dirty report → saved-PDF new tab made one mocked export GET while original checkbox stayed unchecked and Save changes remained visible; explicit Save produced a one-entry report while the journal retained two entries. Fixture exports are mocked; no export-worker/byte-content claim from those UI probes. Existing export regressions passed. |
| Shared baseline protection | Actual shipped guard/client V8 models: registration5 groups, note16, existing automation4 and diagnostic24 passed, including dirty/pending baselines and multipart/Unicode acknowledgment. Native dirty-second-editor confirm is not claimed browser-tested. |

Fixtures use fresh temporary standalone instances, synthetic cases/users and fail-closed tool POST routes. They launch no engines, workers, agents or real exports; outbound `socket.create_connection` is denied. File-controlled failure/closure/revocation and filler events affect only disposable fixture data. No production cases, settings, participants or device commands are touched.

Focused/affected check results and remaining browser evidence are recorded in the final task handoff. Independent exact-head review and required full aggregate remain pending until the candidate is frozen. This is one bounded application task, not whole-app coverage.
