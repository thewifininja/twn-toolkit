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
- Automatic token/choice-control generation does not make an untouched form dirty. Changes to the runbook and explicit connection choices are tracked separately by the existing unsaved-draft guard. Browser reload completed normally after automatic review; checking an exception produced a tracked draft that survived refresh.
- Review errors preserve the current credential fields and choices. Automatic requests never serialize credentials. An accepted submission clears the password through the existing job UI.

## Validation coverage

Automated affected suite: **104 passed** (Bulk SSH workflow/jobs/commandlets/security and terminal streams). This includes eleven new Bulk SSH tests covering review without execution/admission, unsigned/unconfirmed rejection, repeated admission, mixed host exceptions reaching mocked connections, stale port and unknown target rejection, changed saved commands, corrupted retained host choices, host-specific retry flags, and changed-key rejection despite an unrecognized-key exception. Existing worker interruption, cancel, ownership, access revocation, expiry, direct/legacy and profile-edit tests also passed.

Browser observations used only a separate temporary database and synthetic `.test` hosts, with no scheduler or worker and outbound connections blocked. Confirmed:

- automatic initial review; explicit all-host choices and partial-selection indicators;
- refresh and runbook edits retaining current choices and credentials, demonstrated by successful fixture-only admission after refresh;
- changing port clearing choices and refreshing before enabling Run;
- injected review failure keeping Run disabled, then successful retry/admission without reentering credentials;
- delayed preview response arriving after the final runbook action was removed: no token restored and Run remained disabled;
- returning to Hosts and then Review & run retaining the runbook and explicit choices;
- a fresh page starting with no exceptions; cancelling an empty draft clearing its exceptions before a new runbook; desktop and 600px layouts, including screenshot inspection and no horizontal document overflow.

Not performed: real host execution, live trust changes, actual device negotiation, remote-agent deployment, or a live rollout of this candidate. The normal live trial remains separate. Review generation requires the updated server; remote nodes must receive a compatible application update before this UI is offered there.

## Aggregate revocation-test diagnosis

The final aggregate on `c3eb0b6` had 2,458 passing tests and 481 passing subtests, with one failure in the unchanged terminal mTLS test. Its send after Agent revocation raised `BrokenPipeError` before the test reached its expected receive-side disconnect assertion. Isolated passes alone were not treated as a diagnosis.

The test now controls both orderings with events around the real relay authorization callback: (1) legitimate owner output wakes the revoked relay and the test waits for its descriptors to close before attempting the viewer write; (2) rejection waits until the viewer write completes, then closes the relay. Both use actual loopback mTLS, the real authorization predicate and socket pump. Both require disconnection, absence of revoked input in retained output, a surviving owner session, ticket cleanup and database integrity. The first path deterministically reproduces the original failed write; the second preserves the original receive-side rejection assertion. No production relay, transport, authorization or trust code changed. The expanded terminal module passed all 14 tests.

## Independent review follow-up

An independent source/security review found a direct/legacy recovery problem: the new port-bound token rejects a changed port, while runbook-only summary code disabled Refresh on pages with no runbook. The summary now leaves direct/legacy refresh controls alone. A browser check changed port 22 to 2222, refreshed explicitly and successfully admitted a synthetic run with the new signed plan. An automated regression checks stale-port rejection, refresh without admission and explicit admission with the new port. Automatic review request-key observations also confirm omission of credentials, execution acknowledgment, exception selections, draft bookkeeping and the previous token. The independent reviewer rechecked the fixes and found no remaining blocking issue; this is source review rather than deployment or publication approval.
