# Bulk SSH: one review and an explicit run boundary

Scope: the saved host-matrix runbook flow. The direct/legacy submission flow remains compatible. No version, schema, authentication, certificate, or persistent SSH trust changes.

## Interaction changes

Before: build runbook → click Preview → enter credentials and select fleet-wide connection exceptions → check a second execution acknowledgement → click Run.

After: build runbook → review prepares automatically → enter credentials and choose any connection exceptions → click **Run reviewed actions**. Run is the explicit execution acknowledgement. A fleet needing both exception types can use two clearly scoped “all listed hosts” checkboxes, with individual host choices still visible. Strict defaults require neither exception checkbox.

The signed command-plan check remains server enforced. Refresh review is a recovery action, not a mandatory stage. Adding, removing or reordering an action invalidates the current token immediately and automatically prepares another review. Removing the final action cancels the draft plan and clears its connection exceptions. Empty, failed and pending reviews keep Run disabled; older responses cannot restore an invalidated review. Changing the SSH port clears connection choices and invalidates the review. Newly issued tokens bind the SSH port as well as the existing command/host digest; existing pre-update tokens retain their original compatibility behavior until normal expiry.

## Safety and state

- Automatic review resolves commands only. It sends neither login credentials nor connection permissions, admits no job, performs no SSH connection, and changes no saved profile.
- Unrecognized-key and legacy-algorithm exceptions are explicit, off by default, and retained only as current page choices. They are carried through refresh for unchanged host names; a page reload starts with no exceptions. They do not create saved defaults.
- Each host receives only its selected exceptions, even if a request also includes old fleet-wide flags. Unknown/unreviewed host choices are rejected. A changed key still fails verification; allowing an unrecognized key never calls the key replacement/retry path.
- The existing separately confirmed, fingerprint-pinned changed-key retry remains intact. Its retry token carries the specific host's legacy setting.
- Admission continues to use the signed-preview receipt for deduplication. Repeated submissions recover the same job. Cancellation, durable intent, interruption outcomes and access/ownership checks retain their existing implementation.
- Review errors preserve the current credential fields and choices. Automatic requests never serialize credentials. An accepted submission clears the password through the existing job UI.

## Validation coverage

Automated focused suite: **89 passed**. This includes ten new tests covering review without execution/admission, unsigned/unconfirmed rejection, repeated admission, mixed host exceptions reaching mocked connections, stale port and unknown target rejection, changed saved commands, corrupted retained host choices, host-specific retry flags, and changed-key rejection despite an unrecognized-key exception. Existing worker interruption, cancel, ownership, access revocation, expiry, direct/legacy and profile-edit tests also passed.

Browser observations used only a separate temporary database and synthetic `.test` hosts, with no scheduler or worker and outbound connections blocked. Confirmed:

- automatic initial review; explicit all-host choices and partial-selection indicators;
- refresh and runbook edits retaining current choices and credentials, demonstrated by successful fixture-only admission after refresh;
- changing port clearing choices and refreshing before enabling Run;
- injected review failure keeping Run disabled, then successful retry/admission without reentering credentials;
- delayed preview response arriving after the final runbook action was removed: no token restored and Run remained disabled;
- returning to Hosts and then Review & run retaining the runbook and explicit choices;
- a fresh page starting with no exceptions; cancelling an empty draft clearing its exceptions before a new runbook; desktop and 600px layouts, including screenshot inspection and no horizontal document overflow.

Not performed: real host execution, live trust changes, actual device negotiation, remote-agent deployment, or a live rollout of this candidate. The normal live trial remains separate. Review generation requires the updated server; remote nodes must receive a compatible application update before this UI is offered there.
