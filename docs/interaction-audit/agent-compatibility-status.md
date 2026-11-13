# Agent approval and GUI compatibility status

The Mainframe previously labeled every nonmatching or missing protocol report “GUI update required,” including a newly approved Agent that had not sent its first authenticated status report. Enrollment updates the liveness timestamp itself, so the same row could misleadingly appear Online.

This UX-only change distinguishes waiting for the first report, a report missing protocol information, a reported protocol mismatch, and compatible reported protocols. Waiting is informational and the connection column says Awaiting heartbeat. A mismatch shows reported and required protocol numbers. Copy no longer implies that GUI compatibility diagnoses expired credentials or that re-enrollment can never be needed for another failure.

Authorization and protocol gates are unchanged: GUI selection still requires an approved online Agent, its GUI capability, and exactly supported job/GUI protocols. This change issues no credentials, changes no trust records, and adds no recovery path.

Evidence: source review of enrollment timestamps and status recording; isolated tests cover approval→first report, malformed/missing/mismatched protocols, same-identity transition to compatible status, selection fencing, and rendered Mainframe copy. Runtime observation of one repaired development Agent was read-only; no repair actions were performed by this audit. Full-suite and independent-review results accompany the tested candidate.
