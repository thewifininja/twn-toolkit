# FortiAuthenticator inventory jobs

MAC Devices and MAC Group Memberships queue read-only inventory work. The page
returns immediately; the automation worker runs the appliance request in a
separate process with the configured diagnostic deadline. The result link shows
progress, supports cancellation, and can be reopened without contacting the
appliance again. Start the automation worker if the page reports a stale scheduler
heartbeat. Deploy web and worker code together before submitting these new jobs.

Each run saves an encrypted snapshot of its profile, submitting user, and the
recording case selected at submission. Editing a profile or switching cases does
not change queued work. Cancel and resubmit to use changed settings. Results and
downloads require both the original owner's identity and the matching tool
permission. Administrators do not automatically gain another user's downloads.

The preview contains at most 500 records, in pages of 100, with fields shortened
to 512 characters. CSV exports include the complete inventory returned by the
bounded appliance client. Spreadsheet-safe CSV escapes formula-looking values;
Raw CSV preserves them. Generated case evidence always uses the raw CSV. A failed,
cancelled, or expired run does not offer a partial download. A failure while
recording case evidence is logged and never automatically reruns the appliance
request; check the case-recorded notice before relying on case attachment.

Settings → Operations → Background diagnostic limits controls concurrency,
queue/user capacity, deadline, retention, and the inventory export file limit
(default 128 MiB, adjustable from 1 to 1024 MiB). Each new export retains its
starting file limit. Admission reserves space for raw CSV, downloadable CSV, and
a possible case copy, in addition to diagnostic result headroom. These checks
coordinate diagnostic jobs; they are not a reservation shared by every other
writer on the instance. The appliance client's own pagination/response limits
still apply. A larger file limit does not remove the job deadline or those bounds.

CSV files use owner-only filesystem permissions, but are not encrypted at rest;
protect the instance storage accordingly. The scheduler removes temporary and
expired exports after worker ownership is released. Case evidence has its own
retention. Downloads return private/no-store responses and support byte ranges.
The GUI tunnel's configured response limit still applies; use direct Agent
access for exports larger than the tunnel can carry.

The existing `.csv` POST URLs now redirect to a job page instead of returning a
file synchronously. Integrations using those URLs must wait for completion and
follow the download link. MAC cleanup previews and mutations are separate flows;
this change does not alter their execution.
