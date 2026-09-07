# FortiGate rename previews

Both discovered-object and CSV rename workflows require a dry-run preview before
live application. Posting a CSV directly in live mode is rejected, even if a
confirmation field is supplied. CSV previews use the same confirmation form as
object previews.

The results page identifies the profile, target origin, endpoint, default VDOM,
and each row's VDOM. Apply requires the signed preview returned with that page.
It is bound to the authenticated user, toolkit instance, task, complete saved
profile configuration (including credentials and TLS policy), effective endpoint,
and exact ordered rows. Changing any of those inputs invalidates it. Profile
edits in another tab also require a new preview. The server checks the binding
before creating the FortiGate client for live execution.

The expiry policy is centralized in `RENAME_PREVIEW_MAX_AGE_SECONDS` in
`rename_preview.py`, currently 15 minutes; the UI derives its displayed duration
from that value. Changing the toolkit signing key invalidates existing previews.
The token contains a keyed digest, not profile credentials or a copy of the rows.
Target display omits URL credentials, paths, and query strings.

A dry run describes intended operations; it is not a device-configuration
snapshot or a remote reservation. Device state can still change before Apply.
Tokens are not one-time receipts and do not provide exactly-once execution.
After an interrupted live request, reconcile the device and results before
retrying. Existing older preview pages must be regenerated after this update.

This contract covers FortiGate AP and switch rename tasks. Switch ordering and
FortiAuthenticator cleanup have separate preview/apply flows.
