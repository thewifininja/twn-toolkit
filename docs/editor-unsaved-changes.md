# Unsaved automation edits

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

`unsaved-forms.js` currently opts in the four automation editor families with
`data-unsaved-form`. It snapshots controls after their synchronous editor setup,
including dynamic and disabled fields, and compares current values on departure.
`data-unsaved-initial="true"` marks server-returned validation drafts. Its submit
handler runs after existing validation and consumes a navigation exemption once.
It does not replace validation, serialize requests, replay submissions, or alter
cross-tab conflict handling. Other editors and fetch-based saves need their own
integration and acceptance before opting in; this does not provide whole-toolkit
draft protection.
