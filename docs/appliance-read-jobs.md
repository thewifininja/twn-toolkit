# Supervised appliance reads

FortiGate field discovery, data previews, rename-object discovery and CSV exports,
plus FortiGate/FortiAuthenticator connection tests, now queue through the existing
diagnostic scheduler. Read requests return promptly; the worker uses an encrypted
snapshot of the original profile, task options, user and recording case. Changing
the active case or editing the profile after submission does not retarget a run.

The browser polls discovery and preview jobs inline, offers an Open run link and
cancellation, and discards responses if profile/endpoint/field inputs changed.
Navigation remains available; recent-run links on the original task/profile pages
return to retained results. Rename editor departure and reload guards preserve
unsaved work. Connection tests and exports redirect to retained result pages.

Settings → Operations controls existing diagnostic concurrency, queue/user limits,
deadline, history and retention. Inventory export file size applies to FortiGate
and FAC exports. These limits are captured at submission. Export CSV rows stream
into shared private write reservations; raw case evidence stays lossless and
spreadsheet downloads preserve formula-looking text safely. No complete CSV string
is assembled by the worker. Appliance response/flattened row collections remain
in memory under existing client response limits and the supervised deadline.

Browser previews show at most 100 rows/64 columns, shortening values beyond 512
characters with an explicit notice. Full CSV retains all rows/values. Field
discovery supports 256 columns and 512-character samples. Rename discovery rejects
inventories over 500 devices instead of truncating identities; use a scoped
endpoint or CSV workflow. JSON results must fit a 1 MiB envelope. These presentation
envelopes are code constants; execution and file quotas remain operator settings.

Only the submitting user with current access to the original task can view, cancel
or download its result. Files are private mode600 plaintext artifacts outside
served datastore roots; retention and worker ownership govern cleanup. Downloads
are private/no-store and support byte ranges; the finite GUI tunnel response limit
still applies. Cancellation/deadlines terminate the child; interrupted runs are not
automatically replayed. Audit/case outcomes keep original actor and case attribution.

Deploy web and automation workers together. Discovery endpoints now return202 with
job/status/cancel URLs; completed status includes data. Export/connection test POSTs
now return303 to job pages. Direct integrations must follow this job lifecycle.

Signed rename application, switch-order operations and FAC cleanup remain separate
mutation workflows; this change does not alter their reviewed-target safeguards.
