# Remote Terminal: connection attempt and recovery

Scope: choose a saved host or temporary Quick Connect, inspect an ended session,
prepare a new connection, and recover uncertain admission without discarding a
connection draft. This is one complete task batch, not an application-wide sign-off.

## Source findings and resulting behavior

- An ended/error/interrupted session previously offered retained scrollback but no
  next connection action. **Connect again…** now opens Quick Connect for review.
  The old session/output remain separate. Active sessions still restore the same
  shell; they do not show Connect again.
- Prefill copies only historical public destination, username and console line
  settings. It sends no historical `host_id` or saved credential, leaves password
  blank, and resets unknown-key/legacy exceptions off. The dialog explicitly says
  this is a NEW connection and that Connections uses current saved-host settings.
  A deleted or newly private saved host therefore grants no library/credential
  access through this path. New admission retains the existing authorization and
  protocol/credential validation routes.
- An unfinished Quick Connect draft is kept when opening recovery from another
  session. Replacement requires an explicit in-dialog action. Cancel leaves that
  draft in page memory. Navigation uses the existing unsaved-form guard; passwords
  are not placed in browser storage or URLs.
- Concurrent starts in this page are fenced. During Quick Connect admission its
  fields are locked and Cancel/Escape explains that closing does not stop an
  already accepted shell. A bounded request failure keeps the inputs and clearly
  distinguishes an unconfirmed outcome from a validation rejection. There is no
  automatic retry. Admission controls unlock when the POST receipt arrives;
  terminal-output restoration is separate, bounded and fenced against stale
  selection responses. A missing output response cannot retain a one-time password
  or lock all new connections. Automatic output retries are reads, not new starts.
  This is a client guard, not cross-tab server idempotency.
- **Refresh recent sessions** reloads current owned records without reconnecting.
  This provides a way to check uncertain admission while preserving the draft and
  active shell. Its GET route uses the same permission and ownership checks as the
  existing session manager (including existing orphan-state reconciliation).
  The response merges recent history with all current owned active shells, so an
  older live shell is not hidden by the 24-record recent-history limit.

## Evidence

**Source inspected:** Remote Terminal manager, Quick Connect/saved host controls,
workspace/history, start/restore/output routes, session public serialization,
current saved-host credential resolution and existing permission gate.

**Tested with synthetic databases/mocked transport:**

- `test_remote_terminal_task_flow`: empty/owned/foreign retained records; stopped,
  error and interrupted states; private control metadata excluded; revoked tool
  permission rejected; no start/connection call from refresh; active shell older
  than 25 newer completed records remains present without duplicate IDs
  (**6 passed**).
- Existing remote session, connection, library workflow, connection management and
  MSO policy modules: **95 passed, 12 subtests passed**. Combined final focused run:
  **101 passed, 12 subtests passed** (36.29 seconds, including active-history
  retention follow-up).
- Both changed JavaScript files compiled successfully in V8 (syntax only).

**Browser verification pending parent:** this worker's CUA inventory has no
browsers. A dedicated loopback fixture at port 5103 uses a new temporary instance,
standalone role, synthetic saved credentials and ended SSH/Telnet/console records.
No scheduler/agent/worker is launched; outbound connections are blocked and console
device enumeration is mocked. Its admission response is a simulation, not real
transport execution. Browser scenarios: new-session review/defaults; keep/replace
existing draft; cancel/back; keyboard/narrow/long history; validation and uncertain
response; pending duplicate initiators; original scrollback retained after simulated
admission. Parent records observed results and full exact-head aggregate separately.

**Unverified:** real devices, real credential negotiation, actual agent-offline
transport, all palette/density/text-size combinations, and cross-tab admission
races. No live service/settings/trust changes or real host commands were performed
for this batch.
