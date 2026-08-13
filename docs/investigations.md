# Investigations and case journals

Investigations is the toolkit workspace; each individual troubleshooting record
inside it is a case. Cases turn individual toolkit actions into a durable
record. The shared persistence and UI contract now covers the first finite
diagnostic set; long-running Multi-Ping and SSH/Telnet session capture remain
separate lifecycle slices.

## Operator workflow

Each user may have one open case. An open case is either:

- `recording`, which accepts supported tool events automatically; or
- `paused`, which suppresses automatic tool events while still accepting
  deliberate notes and evidence uploads.

Closing moves the case to the internal `completed` state. Closed case journal
events and evidence metadata are read-only. Report inclusion is presentation
metadata and remains editable after closure; changing it never changes or
deletes source evidence. A closed case can be reopened when no other case is
open. Reopening returns it to `paused`, clears its terminal timestamp, and adds
an immutable `investigation.reopened` journal event; the operator must explicitly
resume automatic recording. Starting a new case does not alter closed work.

The global banner makes the current recording context visible on every permitted
page. The case workspace uses tabs-first Journal, Evidence, and Report
views on desktop and mobile.

## Persistence and ownership

`instance/investigations.sqlite3` is the source of truth for cases,
journal events, and evidence metadata. It uses SQLite WAL mode, a busy timeout,
a fresh-instance initialization lock, foreign keys, and owner-only file modes.
All queries that expose case data include the owning user ID.

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
case data.

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

## Finite diagnostic integrations

The first finite-result set records DNS Tester, TCP Port Scanner, Traceroute,
NTP Tester, Path MTU Tester, and Wi-Fi / LAN Speed Test runs while the current
case is recording. Each route retains normalized targets, non-secret bounded
settings, summary metrics, and the structured results needed to reproduce the
screen result in a report without rerunning the diagnostic. Browser speed tests
are labeled specifically as browser-to-toolkit measurements, not internet speed
tests.

Streamed traceroutes record one event when each destination finishes. A client
disconnect before completion does not invent a completed result. Multi-Ping and
terminal sessions will instead need explicit started, stopped, disconnected,
and reattached lifecycle events plus bounded rollups.

## Reporting

The report is a deterministic view derived from retained journal events and
artifact metadata. Its first layer is a compact chronological case timeline with
summary facts. Structured diagnostic results appear on individually numbered
detail pages linked from the timeline, followed by an evidence appendix when at
least one file is selected. The toolkit renders the saved selection directly as
a downloadable PDF; browser printing remains available as a convenience.

**Download case package** builds an ephemeral ZIP containing:

- `case-report.pdf`, generated from the same saved selection;
- each selected original under `evidence/`; and
- `manifest.json`, with case metadata, included event IDs, result labels, file
  names, byte counts, UTC timestamps, and SHA-256 hashes for the PDF and every
  evidence member.

Package creation re-reads and hashes each selected evidence file. A missing or
changed file stops the export instead of producing a package whose manifest no
longer matches its contents. The ZIP is streamed from temporary storage and is
not duplicated into the case's `Reports` folder.

The Report contents editor includes or excludes individual timeline events and
evidence files. It changes only each item's `report_placement`; the underlying
event payload, artifact metadata, and stored file remain untouched. This editor
therefore stays available after the case closes even though the journal and
evidence library are immutable.

`investigation_reporting.py` is the presentation registry. It converts retained
events into shared timeline facts and either a generic detail table or metric
group. Report templates do not contain tool-specific result branches. Add a
registry builder when a new event needs more than its human-readable summary.

Future generated narrative may summarize or propose findings, but it must be
clearly labeled as generated interpretation, cite retained event IDs, and remain
separate from immutable source evidence.

## Adding another tool

After a meaningful tool run finishes, call
`record_current_investigation_event` with a fresh operation ID and the event
contract above. Record start time before execution and completion time after the
result is known. Normalize and sanitize data before the call. Add store or route
tests proving successful and failed outcomes, pause behavior, retained details,
and deterministic report rendering for any new result presentation. Register
the tool's report builder in `investigation_reporting.py`; keep presentation
logic out of the shared Jinja template.
