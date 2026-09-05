# Session activity and supervisor recovery

## Browser sessions

Settings → Authentication policy retains the administrator-selected idle timeout
(0 disables idle expiry). Background requests, live-tool polls, session probes,
and automatic reloads do not renew it. The server checks expiry and account
revocation before accepting activity; an expired session must sign in again.

Visible-page keyboard, pointer, input, wheel, and touch interaction sends a
same-origin activity signal, throttled to at most once every five seconds per
tab. Synthetic DOM events and events while the document is hidden are ignored.
Browser-reported user-initiated navigation also renews activity. Idle accounting
has this small sampling interval; it does not track every input event precisely.
Simply watching a terminal or results stream is inactivity. A long-running task
continues under its own worker lifecycle; browser login expiry does not cancel it.

Tabs in the same browser session share the login cookie. A passive tab can remain
signed in while another tab is used, but cannot keep the session alive itself.
Agent pages send session probes/activity to their Mainframe login host, so the
agent's local policy does not replace the coordinator's authentication policy.

An expired page displays a sign-in notice without navigating away or clearing
its fields. The link opens sign-in in a new tab; return to the original tab to
continue. This preserves the current page, not a durable draft: browser reloads,
closing the tab, or application-specific rerenders may still lose unsaved work.
A failed network check retries and does not itself prove expiry. Background
browser suspension may delay the notice; the server still enforces the timeout
on every protected request. Password changes, disabled accounts, and logout
remain effective regardless of activity.

`GET /session/activity` reports remaining idle time without renewing it or
writing a valid session cookie. `POST` requires the explicit custom activity
header and passes the application's origin checks. Both successful responses
and expired-session responses disable caching. Browser activity is an interaction
signal, not proof of a human operator or a defense against malicious same-origin
code. Existing signed-cookie session storage is unchanged. No database migration
or new absolute session lifetime is introduced. Reload pre-upgrade tabs to load
the new activity script; agent pages also need updated UI assets to emit these
signals. Browsers without JavaScript rely on user-navigation
Fetch Metadata headers; they cannot report editing within a stationary page.

## Supervisor

Each scheduler/transfer-service health check and restart has its own exception
boundary. A timeout, unavailable command, malformed service settings, or failed
probe is written to the supervisor log while the sweep continues to other
services. Nonzero restart exits are also reported. Managed iPerf restoration
has an independent failure boundary and cooldown. Failed heartbeat publication
is logged without ending recovery, and malformed/nonfinite/future timestamps
are not accepted as fresh worker heartbeats.

Recovery policy is centralized in `supervisor_worker.py`:

| Policy | Current value |
| --- | ---: |
| Restart command timeout | 30 seconds |
| Cooldown after a restart attempt or service failure | 30 seconds |
| Delay between sweeps | 5 seconds |
| Maximum scheduler heartbeat age | 20 seconds |

These retain the existing timing defaults and are code-level settings, not new
administrator form fields. Cooldowns use monotonic time, so wall-clock changes
cannot collapse the retry allowance. Active service-operation locks still
prevent competing restarts. Shutdown stops starting further service checks;
an already-running restart may take its remaining command timeout to finish.
Ownership-aware PID/heartbeat cleanup and singleton-lock release run on exit.

Supervision remains sequential: a slow restart can delay later checks within
its command timeout, and iPerf restoration uses its existing internal worker
bounds. This change contains failures; it does not promise parallel recovery,
instant shutdown, or immunity to a blocked filesystem call. Supervisor heartbeat
presence indicates supervisor progress, not that every managed service is healthy.
