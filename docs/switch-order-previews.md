# Switch-order review and application

Loading switches returns a signed binding for the authenticated user, instance,
complete profile configuration, VDOM, and original ordered switch IDs. The UI
shows the loaded profile, target origin, and VDOM alongside the move preview.
Changing the profile or VDOM discards that loaded state. Late load responses
cannot populate the editor for a newly selected target.

Checking the confirmation box asks the server to validate the loaded binding
and issue a second binding for the exact original and desired orders. This is a
local validation request, not another device inventory query. Apply remains
disabled until it succeeds. Editing the order cancels that confirmation; late
confirmation responses cannot authorize a different order.

The server validates Apply's binding before constructing the device client,
then reloads the device order. Changed inventory or a changed original order
aborts before any moves. Existing inventory checks, per-move failure reporting,
and final order verification remain in place. A successful verified apply
returns a fresh loaded-order binding for another review.

Target and editing controls are disabled while an apply is active. An error or
uncertain response clears authorization and requires reloading/reconciling the
device before another attempt. The browser does not automatically retry Apply.
Older pages without these bindings must be refreshed before applying.

Loaded and confirmed bindings each expire after the shared preview lifetime,
currently 15 minutes (`PREVIEW_MAX_AGE_SECONDS` in `preview_binding.py`). Tokens
contain a keyed digest rather than profile credentials or inventory. The shared
signer preserves the existing FortiGate rename-token format.

This is not a device lock or exactly-once operation receipt. Another device
administrator can still change configuration after the final preflight read.
Do not infer a completed or untouched device from a lost response; reconcile the
current order and available results. These safeguards cover switch ordering;
other appliance changes retain their own operation contracts.
