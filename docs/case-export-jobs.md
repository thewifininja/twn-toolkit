# Background case exports

PDF reports, selected case packages, and portable cases now return a queued job
page immediately. The automation worker builds them in a separate process under
the diagnostic deadline. The page supports progress, cancellation, and a retained
download. Refreshing or downloading a completed result does not rebuild it.

The worker captures a consistent database snapshot when it starts, including
case access and report selection. Changes made while an export is queued can
therefore affect its contents; changes after the snapshot do not. Evidence files
are streamed and checked against their recorded sizes and hashes. A changed file
fails the export. Failures/cancellation never offer a partial archive, and work
is not automatically replayed after an uncertain worker exit.

Settings → Operations → Background diagnostic limits controls:

- Export input metadata: default 16 MiB, adjustable 1–64 MiB. This is checked in
  the same database snapshot before event payloads are loaded. Evidence file
  contents are streamed rather than included in that in-memory metadata budget.
- Export file size: default 128 MiB, adjustable 1–1024 MiB. Writes enforce the
  limit during archive construction; diagnostic admission accounts for queued
  output disk headroom.
- PDF detail cells: default 50,000, adjustable 1,000–200,000. Large detailed tables
  fail explicitly instead of silently truncating the downloaded report.
- The existing diagnostic concurrency, queue, user, deadline, and retention rules
  also apply. A run keeps its starting export limits; cancel/resubmit to change them.

PDF/package exports include the complete saved selection, with original detailed
results. Portable cases include the complete journal and evidence, independently
of report selection, and retain the existing portable-format limits/provenance.
A limit failure requires reducing the selected report or deliberately increasing
an appropriate limit. Input/row limits are workload bounds, not a hard process-RAM
quota; higher limits can increase worker memory and execution time.

Downloads require the submitting user and current access to the case. Revoked
collaborators cannot retrieve completed exports. Output files use private
owner-only permissions, are not encrypted at rest, and expire with diagnostic
retention. Cleanup waits until the worker releases ownership. Responses are
private/no-store and support byte ranges. The GUI tunnel response limit still
applies; larger files may need direct Agent access. Case exports and FAC CSV
exports share physical write reservations with incoming uploads. Abandoned
staging is reclaimed after its process exits. Queued headroom accounting covers
diagnostic jobs; it does not guarantee capacity against other writers or external
processes on the disk.

Deploy the web and automation workers together. Existing `.pdf`, `.zip`, and
`.twncase` GET URLs now redirect to a job page. Integrations expecting an immediate
file must wait for completion and follow its download link. The worker records
export outcomes; actual downloads retain their format-specific audit actions.
