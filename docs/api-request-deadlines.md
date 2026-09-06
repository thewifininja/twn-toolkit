# API request deadlines

The API Request Tester and automation HTTP action use the selected timeout as a
whole-operation budget (0.2–30 seconds). It includes child startup, system DNS,
connection and TLS setup, sending the request, response headers, body transfer,
and returning the result. Very short budgets can expire during startup on a busy
host. The existing connect/read idle timeouts remain secondary safeguards.

Each call supervises one child process. Input travels over stdin, including URL,
headers and body; it is not put in argv or temporary files. The caller kills and
reaps unfinished work at its deadline, including on interruption. A child watchdog
also exits at the deadline or when its original parent disappears. Normal process
scheduling and cleanup add small overhead; this is not a real-time guarantee.

No timeout triggers a retry. A POST/PUT/PATCH/DELETE may already have executed
remotely when its response is lost. Check remote state before manually retrying.
The timeout error explicitly says that no complete response was confirmed.

TLS verification and environment proxy behavior are preserved. Redirects are
reported without following them. Responses retain the existing 1 MiB decoded
body cap, redaction, and explicit stream closure. Runtime response data exists in
process memory and pipes, not a new disk result store. Existing callers retain
their own history/case policies.

This boundary applies to manual and automation API requests on the executing
instance. Restart application/automation workers after upgrading that instance.
It does not migrate the web route to the background diagnostic queue or establish
a fleet-wide connection budget: each concurrent caller can create one child.
Those concurrency and asynchronous execution audit items remain separate.
