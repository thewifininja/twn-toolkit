# Remote Terminal streaming

Development v0.25.6 uses an on-demand WebSocket for a visible, active terminal.
Keystrokes and output travel over that connection; the browser no longer repeatedly
requests output. SSH, Telnet and serial transports wake their session reader when
data is available. No speculative local echo is used, so password prompts and
terminal control sequences retain the remote device's behavior.

Through an Agent, one attachment operation opens a connection outward over its
existing certificate-authenticated Mainframe listener. Input and output then pass
directly through the relay, outside the generic HTTP job queue. The Agent does not
open a new inbound port. Both ends advertise/support `system.terminal.stream@1`;
older builds and proxies without WebSocket support retain the HTTP path.

## Idle and detached sessions

- With no terminal viewer attached, there is no terminal stream or output polling.
  Ordinary Agent enrollment, status and work channels keep their existing cadence.
- A visible idle terminal waits for data. Small keepalives maintain the browser
  and relay connections; it does not repeatedly request empty output pages.
- Hiding the browser tab detaches its viewer. The remote shell continues, and
  returning catches up from the retained cursor. Closing the viewer also preserves
  the shell; use **Stop** to end the session.
- Scrollback checkpoints remain separate, occasional requests when output changes.
  They preserve recovery and do not poll an idle terminal.

## Delivery and access

Input is ordered and acknowledged. An input item whose acknowledgement is lost is
never automatically resent; the interface reports the uncertain delivery. Reopening
a viewer replays output only. Oversized input and a growing unsent queue are bounded.

Each viewer must own the session. Mainframe access additionally requires an approved
Agent and a current administrator account. Cross-origin browser upgrades are rejected;
account changes and Agent revocation end access. Short-lived attachment tickets are
bound to one Agent and disappear when the viewer disconnects. They cannot start a shell.

The web server uses 16 threads per worker and admits up to eight streaming viewers
per worker, leaving capacity for ordinary requests. Session owners and Agent relays
also cap concurrent viewers. Listener streams share the total connection budget and
control reserve, while preserving the Agent's regular/interactive polling allowance.
Capacity exhaustion falls back to the compatible HTTP path.

## Verification

Use a disposable echo endpoint to compare keystroke-to-render time locally and through
an Agent. Measure empty output requests separately from checkpoint and ordinary status
traffic. Repeat with two viewers, tab hiding/return, reconnect, and large output. A
quiet echo fixture isolates toolkit latency; real devices and links can add their own
delay. Test SSH/Telnet/serial behavior with the protocols and hardware you operate.
