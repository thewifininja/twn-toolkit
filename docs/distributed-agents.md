# Distributed toolkit architecture

Status: implemented foundation

## Product model

Every TWN Toolkit instance always retains its complete local functionality. An
instance additionally has exactly one coordination role:

- `standalone`: no distributed listener or outbound control connection.
- `mainframe`: accepts enrolled agents and may dispatch supported jobs to them.
- `agent`: maintains an outbound connection to one mainframe while continuing
  to serve and execute all local workflows normally.

Standalone remains the default for existing and new installations. Changing a
role must never implicitly expose a listener, approve a peer, or erase trust
records.

## Network topology

An agent maintains an outbound series of bounded mutual-TLS long polls to its
configured mainframe. An idle poll is held for 20 seconds, so dormant agents
normally make about three requests per minute without sacrificing interactive
delivery latency. Jobs and tunneled HTTP request envelopes share this outbound
transport. Agents do not require an inbound firewall opening.

An agent may also define one ordered fallback Mainframe URL. Connection, DNS,
timeout, and TLS failures on the primary cause the worker to try the fallback;
an HTTP response never does. A successful fallback remains preferred until the
worker restarts. Both names or addresses must identify the same Mainframe and
must be covered by its listener certificate. TLS verification is never relaxed
for fallback traffic.

Interactive GUI traffic is claimed by three concurrent outbound lanes and is
removed after the waiting browser response consumes it. Durable fleet jobs use
the separate heartbeat lane and remain queryable. Terminal output, input, and
resize requests may therefore progress independently; these lanes are also the
upgrade boundary for future ordered stream frames.

The mainframe listener has an explicit list of local IP addresses and a port.
Wildcard addresses (`0.0.0.0` and `::`) are supported but must be deliberate.
The listener is separate from the browser listener so its protocol, client
authentication, limits, and exposure can evolve independently.

The listener admits at most 32 TCP connections before starting TLS work. Each
admitted connection gets five seconds to finish its handshake and then one
absolute ten-second budget to read HTTP headers and body. Sending bytes slowly
does not restart that budget. Response writes have an independent ten-second
I/O timeout; legitimate server-side long polling is outside the request-read
budget. Failed or expired connections release their slot, while unexpected
handler errors remain visible in server error reporting.

Optional advertised hostnames or public IP addresses are explicit certificate
identities, separate from local bind addresses. This supports DNS and raw TCP
port forwarding such as public TCP 443 to internal TCP 5051. Directly binding a
local port below 1024 requires operating-system privileges and is discouraged.

## Trust and enrollment

Operators never manually create or exchange secret keys. Each instance creates
an owner-readable Ed25519 identity on first use. The private key never leaves
that instance.

Initial enrollment is an unauthenticated, rate-limited request carrying the
agent public identity and bounded system metadata. New requests are rejected by
default. An administrator must open enrollment for an explicit 1–1440 minute
window, which closes automatically and may be closed early. Closing the window
does not disconnect approved agents or prevent an already-created pairing from
finishing. The mainframe stores an accepted request as `pending`. Both
instances derive and display the same short pairing code from
the complete ephemeral handshake transcript. A mainframe administrator must
compare that code with the agent display before approving the request.

Approval issues an internal client certificate bound to the stored
device identity. Normal reconnects require mutual TLS and pin both identities.
Revocation is immediate, durable, and audited. An IP address is metadata, never
identity. Enrollment throttling is durable across listener restarts, request
sizes are bounded, and listener concurrency is capped.

The pairing comparison is required: approval based only on an IP address or an
unverified self-signed certificate would leave first contact open to an active
intermediary attack.

## Execution context

The mainframe top bar owns one execution-context selector for each
authenticated user. `This instance` is the default; each online, compatible,
approved agent appears by its administrator-assigned name. The selection is
per-user rather than global so operators may work through different agents at
the same time. It persists across navigation and applies to every supported
tool until the user changes it.

Switching instances preserves the current relative path and query when the
destination supports it. A missing destination route falls back to that
instance's dashboard with a notice. Appearance is stored by mainframe user and
instance, allowing intentional visual separation between systems.

A selected agent renders its own native application through a reverse HTTP
tunnel rooted at `/agents/<id>/ui/`. Its local profiles, interfaces, settings,
history, and tool behavior therefore remain authoritative. The browser talks
only to the mainframe. Generated links and redirects retain the agent prefix,
while shared static assets are served by the mainframe checkout on the same
version stream.

The toolkit never silently falls back to local execution. If the selected agent
disconnects or becomes incompatible, execution is blocked with a clear status
and the operator may explicitly select another context. Offline agents may
remain visible for orientation but cannot be selected.

An agent's own local web interface continues to operate as that instance. The
cross-instance selector is a mainframe-console feature; connecting an agent does
not turn its local interface into another mainframe.

## Authorization

Full-interface access currently requires a mainframe administrator. The agent
accepts the delegated identity only inside its authenticated worker dispatch;
no reusable assertion or agent session credential is exposed to the browser.
The agent's native endpoint remains responsible for validation and local audit.
Fleet jobs remain a separate versioned capability system for orchestration.

## Protocol and compatibility

Messages use a versioned envelope with a stable job identifier, message type,
protocol version, and bounded payload. Peers advertise toolkit version,
protocol range, platform, and capability versions. The mainframe may dispatch a
job only when the selected agent advertises a compatible capability.

The target job contract includes:

- stable job, tool, operation, requester, and target-agent identifiers;
- validated structured input and capability version;
- authorization context, deadline, resource limits, and cancellation policy;
- ordered progress events and one terminal status;
- structured output, bounded logs, and content-addressed artifact descriptors.

The current queue uses one SQLite transaction boundary for enqueue, activation
changes, claims, and completion. Enqueue binds an activation before publishing
the job. Claims reserve the writer before selecting eligible rows, so concurrent
lanes cannot receive the same unexpired claim. Lease time begins after that
reservation. Competing completions retain the first committed terminal result;
late results cannot undo a committed cancellation. Schema initialization uses
the same reservation and preserves existing queue records.

Delivery remains at-least-once: a running job becomes eligible again when its
30-second lease expires. Atomic claims do not establish exactly-once execution.
Renewable leases, attempt ownership, durable operation deduplication, and
reconciliation of uncertain side effects remain execution-contract work. Until
those are implemented, arbitrary tunneled mutations must not be assumed safe to
retry solely because a request timed out. Terminal results remain queryable
after reconnect.

## Execution classes

Fleet automation migrates through explicit adapters even though interactive
administration uses the full-interface tunnel:

1. finite diagnostics (ping, DNS, traceroute, SNMP);
2. streaming diagnostics (scans and captures);
3. managed listeners (syslog, TFTP, FTP, iPerf);
4. artifact-producing workflows and investigations;
5. scheduled/background work;
6. narrowly approved host administration.

System identity and DNS are implemented as initial finite job capabilities.

## Current tunnel limits

Interactive request and response bodies are bounded to 192 KiB before base64
encoding. Shared CSS is served locally by the mainframe. Ordinary pages, forms,
redirects, and small downloads are supported. Large uploads, streaming bodies,
Server-Sent Events, and WebSockets require a later multiplexed streaming
transport and must not silently fall back to local execution.

## Persistence and audit

`distributed_settings.json` stores the coordination role and bounded network
configuration. `distributed_identity.pem` stores the local private identity
with owner-only permissions. `distributed_agents.sqlite3` stores peer identity,
enrollment state, permissions, connection metadata, and revocation state.
`distributed_enrollment_window.json` stores only the enrollment deadline with
owner-only permissions; a missing, invalid, or expired file means closed.
`distributed_jobs.sqlite3` stores queued work, activation bindings, leases, and
results separately from trust records. Both historical queue import paths use
the same implementation and existing schema; no new wire fields are required.

Enrollment request, approval, denial, certificate renewal, permission change,
job dispatch, cancellation, completion, failure, and revocation are audited.
Audit records omit credentials, private keys, raw session traffic, and tool
secrets.

## Delivery stages

1. Configuration, identity, trust-store schema, and pairing primitives.
2. TLS listener/client, enrollment approval, reconnect, and revocation.
3. Agents administration page with live capability and version status.
4. Durable job transport using system identity, then ping.
5. Shared progress, cancellation, result, artifact, and audit plumbing.
6. Tool adapters by execution class, with local-only exceptions documented.
