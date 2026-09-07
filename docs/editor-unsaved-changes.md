# Unsaved editor protection

Automation, reusable action, condition, and schedule editors warn before leaving
with changed fields or dynamic rules/stages. Reverting an edit to its original
value removes that warning. A form returned after server validation fails remains
unsaved, even before further typing.

Saving an editor normally does not prompt about that editor. If another editor
on the same page has changes, submitting a save, preview, or other native form
asks before discarding them. Cancelling keeps the edits and prevents that form
request. A cancelled client-side validation does not authorize later navigation.

This is departure protection, not autosave. Nothing is written to localStorage,
sessionStorage, or a draft endpoint; credentials remain only in the current page
alongside the form values. Browser crashes, forced mobile app termination, and
browsers that suppress departure prompts cannot be covered by this warning.
Native POST delivery failures are not an autosave or recovery guarantee.

## Integration scope

`unsaved-forms.js` opts in the four automation editor families and the RADIUS/SNMP profile editors with
`data-unsaved-form`. It snapshots controls after their synchronous editor setup,
including dynamic and disabled fields, and compares current values on departure.
`data-unsaved-initial="true"` marks server-returned validation drafts. Its submit
handler runs after existing validation and consumes a navigation exemption once.
It does not replace validation, serialize requests, replay submissions, or alter
cross-tab conflict handling. Other editors need their own integration and acceptance before opting in; this does not provide whole-toolkit draft protection.

## Asynchronous profile saves

RADIUS and SNMP editors capture a baseline immediately before sending a save and acknowledge only that submitted snapshot after success. If the user changes fields while the request is pending, or another editor still has changes, the page stays open and reports that unsaved edits remain. Saving a clean final editor reloads normally. HTTP/network errors retain an unconfirmed draft state, even if fields were reverted while the request was pending. In-flight saves prevent automatic reload and warn on departure. Repeated submissions while a save is pending are ignored.

Server-managed `original_name` fields opt out of dirty comparison with `data-unsaved-ignore`; they are updated after a successful save so another edit targets the saved profile. Confirmed SNMP credential renames update dependent selectors and their reference baselines, preserving the identity of each selected credential without treating the rename as another user edit. RADIUS run selectors and duplicate/delete metadata follow confirmed renames. A creation form that remains open becomes an explicitly labelled editor for the saved record; subsequent saves update that record. New records in run selectors and other server-normalized presentation changes may require the eventual reload to appear everywhere.

The shared `TwnUnsavedForms` API provides capture/acknowledge, a dirty-state query, and reference-baseline updates for these integrations. It stores values only in page memory. It does not retry requests or resolve conflicting saves from other tabs. Native automation submit behavior remains unchanged.

## DNS list saves and deletion

DNS query/resolver list saves and deletion update the saved-list controls in place. They preserve both current lists and diagnostic settings. Text entered while a save is pending remains in the editor, while the saved option contains only the server-confirmed submitted values. A later save updates that option without creating duplicate entries. Deleting a saved list leaves the current inputs available as an unsaved list.

Each list locks its naming, selection, and action controls during its save/delete request; its text and the other list remain editable. HTTP/network failures retain current inputs and restore controls. This does not add autosave, departure protection, or cross-tab conflict resolution to DNS. Explicitly loading a different list replaces that list's text, and the existing Duplicate action still navigates. Only the existing selected-profile name is stored in sessionStorage, not list drafts.
