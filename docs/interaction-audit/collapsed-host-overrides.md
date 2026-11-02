# Collapsed individual connection overrides

This focused change starts from the reviewed run-step candidate. It keeps the existing visual style and changes only review layout/client state, plus regression coverage. Server admission, SSH trust, changed-key recovery and algorithm policy are unchanged.

Before: every host's two exception controls appeared below the bulk choices, in a bounded but initially expanded list.

After: bulk choices remain visible. **Individual host overrides · N hosts** is a native disclosure, collapsed by default. Mixed fleets can still override individual hosts. A visible summary counts unrecognized-key and legacy exceptions independently; it updates after bulk changes, individual changes, refresh and port edits. The user's latest disclosure state survives successful refresh. Cancelling an empty runbook still clears its choices.

Strict defaults remain off. The changed-key policy and the visible SHA-1 RSA warning remain outside the disclosure. The review explicitly states that host identities are checked when connecting: it resolves commands, without probing hosts or inventing a count of unresolved keys. Failed/stale review status and the disabled Run boundary remain outside the new disclosure; actual execution-result/recovery pages are not wrapped by it.

## Verification

- Four new markup cases cover one, two and 501 hosts, and a mixed selection. They verify collapsed defaults, visible bulk controls/counts/policy information, retained checked values, and unchanged strict defaults.
- The affected regression selection passed 74 tests, including existing stale-plan, mixed-host, changed-key and admission security coverage.
- Isolated browser checks used separate synthetic instances, no scheduler or worker, and blocked outbound connections. They covered bulk selection with the panel closed; Space/Enter expansion/collapse; partial selection indicators; 500/501 unrecognized-key and 1/501 legacy counts; preserving both closed and open state through refresh; retaining the latest disclosure change during a delayed response; cancelling an in-flight review; clearing counts immediately on port change; and visible injected review failure while collapsed with Run disabled.
- A closed two-host panel admitted a fixture-only job with exactly one host's legacy exception. Stored configuration confirmed that the other host retained strict defaults. No worker executed this job.
- Desktop and 600px screenshots were inspected. At 600px, document width stayed within the viewport and the expanded 501-host list remained bounded to 384px with internal scrolling.
- Independent source/security review found no blocking issue and recommended keeping the SHA-1 RSA detail visible in the bulk label; that suggestion was adopted.

No real hosts, live data mutations, trust changes, deployment, public push, version bump or release were used for this validation. Full-suite results for the final commit are recorded in the task validation record.
