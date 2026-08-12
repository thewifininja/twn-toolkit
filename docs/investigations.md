# Investigation journals

Investigations turn individual toolkit actions into a durable troubleshooting
record. This first vertical slice establishes the shared persistence and UI
contract, integrates DNS Tester, and leaves SSH/Telnet session capture and other
diagnostics for later slices.

## Operator workflow

Each user may have one open investigation. An open investigation is either:

- `recording`, which accepts supported tool events automatically; or
- `paused`, which suppresses automatic tool events while still accepting
  deliberate notes and evidence uploads.

Finishing moves the investigation to `completed`. Completed investigations,
their journal events, and their evidence metadata are read-only. Starting a new
investigation does not alter completed work.

The global banner makes the current recording context visible on every permitted
page. The investigation workspace uses tabs-first Journal, Evidence, and Report
views on desktop and mobile.

## Persistence and ownership

`instance/investigations.sqlite3` is the source of truth for investigations,
journal events, and evidence metadata. It uses SQLite WAL mode, a busy timeout,
a fresh-instance initialization lock, foreign keys, and owner-only file modes.
All queries that expose investigation data include the owning user ID.

Files are stored through `LocalDatastore` beneath:

```text
instance/datastore/Investigations/inv_<random-id>/
├── Evidence/
└── Reports/
```

Uploads inherit Datastore size, quota, free-space, path, and symlink defenses.
Names are normalized and collision-safe. The artifact record retains the stored
relative path, byte count, content type, SHA-256 digest, collecting operator,
timestamp, and the journal event that introduced it.

The toolkit recovery archive already includes top-level SQLite databases and the
Datastore. Profile backup intentionally does not include operational
investigation data.

## Event contract

Journal events are append-only evidence. A supported tool records one sanitized
event after an intentional run, using:

- a unique operation ID for idempotency;
- stable event type and tool ID;
- start and completion timestamps;
- outcome and human-readable evidence summary;
- normalized targets and non-secret parameters;
- aggregate metrics; and
- bounded structured details needed for the report.

The `(investigation_id, operation_id)` uniqueness constraint prevents a retried
request from replacing or duplicating retained evidence. Each JSON field is
bounded to 4 MiB and must be valid finite JSON. A journal failure is logged but
does not turn a successful diagnostic into a failed tool run.

Failed validation may be recorded, but it must not retain raw unparsed input that
could contain unintended or sensitive content. Credentials, tokens, community
strings, passwords, and private keys never belong in targets, parameters,
metrics, details, summaries, or audit records.

## DNS integration

DNS Tester records lookup and bounded load-test attempts while the current
investigation is recording. Events retain parsed hosts/resolvers, mode, record
type, timeout and bounded load settings, outcome, summary metrics, and the
existing structured result payload. The report expands lookup results and load
metrics without rerunning the test.

## Reporting

The first report is deterministic HTML derived from retained journal events and
artifact metadata. It includes the situation, operator, lifecycle state,
chronological evidence, DNS result tables, and a hashed evidence appendix. The
browser print flow provides paper or PDF output.

Future generated narrative may summarize or propose findings, but it must be
clearly labeled as generated interpretation, cite retained event IDs, and remain
separate from immutable source evidence.

## Adding another tool

After a meaningful tool run finishes, call
`record_current_investigation_event` with a fresh operation ID and the event
contract above. Record start time before execution and completion time after the
result is known. Normalize and sanitize data before the call. Add store or route
tests proving successful and failed outcomes, pause behavior, retained details,
and deterministic report rendering for any new result presentation.
