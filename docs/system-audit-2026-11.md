# System audit — 2026-11-11

> Follow-up, 2026-11-11: PR #315 (`fa96366`) merged the dependency lock update;
> its merged-main dependency audit passed. Finding 7 and the original validation
> ledger below describe the pre-update audit snapshot. PR #314 was then rebased
> onto main with the TLS listener test portability fix (#316).
>
> Follow-up, 2026-11-12: PR #318 (`11a41e9`) raised the minimum to Python 3.11
> and retired the Python 3.10 dependency exception; Pillow 13.0.0 and dnspython
> 2.9.2 are now unconditional. See `security-advisories.md`. References to
> Python 3.10 below are historical.
> Current branch validation is recorded in the PR; historical local results
> below are not validation of the rebased head.


Repository-wide review of TWN Toolkit at `efa50d7` (v0.27.0 plus 43 unreleased
local commits), followed by six focused fixes on `claude/repo-audit-2026-11`.
This is a coverage ledger and backlog, not a sign-off. Status words: **tested** = asserted
against isolated synthetic state; **measured** = timed on synthetic state;
**inferred** = source read only; **unverified** = no evidence gathered.

## Repository state when the review started

- Published: `origin/main` = `3ddaaee` = tag `v0.27.0` (released 2026-10-17,
  all six CI checks green). Open PR 313 (Agent certificate renewal) passed CI
  on 2026-10-20 and is unmerged. Open issues: 216, 179, 37.
- Local, unpublished (not part of this pull request): the reviewed head `efa50d7` is 43 commits ahead of
  `origin/main`; none of that stack is pushed. Twenty-two other worktrees and
  about 160 remote branches exist. `codex/agent-lifecycle` holds five further
  unmerged certificate/recovery commits (22 files, +1,895) that are in neither
  this head nor PR 313.
- The primary checkout is also the **running installation**. Gunicorn and six
  workers were serving from it, with live data in its `instance/`, while it had
  the unreleased `codex/plex-network-failure-trial` branch checked out. All
  work here was done in a separate worktree and temporary instances. The live
  service, its data, enrollment and trust were not touched; only file modes in
  `instance/` were listed.

## What the toolkit is

A Flask application (399 URL rules, 274 of them mutating; 233 Python modules;
94 templates) served by Gunicorn (2 workers × 16 threads) beside separate
worker processes: automation scheduler, distributed transport, TFTP, FTP,
SFTP/SCP, and a supervisor that restarts workers and retains logs. State is
local: about twenty SQLite databases plus JSON settings files in `instance/`,
JSON writes serialized by sidecar file locks. Long operations run as supervised
background jobs with retained results rather than inside requests.

In distributed operation a Mainframe keeps a durable job queue. Agents make
outbound mTLS long polls to a dedicated listener (default 5051), claim leased
jobs, and return results. The Mainframe GUI reaches an Agent's own pages by
enqueueing `system.http.tunnel` jobs; terminals attach over a separate upgrade.
Mainframe Synced Objects replicate selected libraries over the same channel.

Request authorization is one `before_request` hook: origin check for mutations,
trusted-host check, session validity, then a registry lookup from endpoint to
tool ID. A registry test fails when a route is neither mapped nor explicitly
listed as self-service, so an unmapped route cannot ship silently.

## Baseline validation

| Check | Result |
|---|---|
| Full suite at `efa50d7`, fresh hash-locked venv, Python 3.12 | 2,588 passed, 5 skipped, 483 subtests, **1 failed** in 800 s |
| The one failure | `test_stalled_client_does_not_block_a_later_request`: `AF_UNIX path too long`. Caused by this review's long `TMPDIR`; passes 1/1 with a short one at the same commit. Not a product defect. |
| Lock provenance, `bash -n install.sh twn`, `pip check` | Passed |
| `pip-audit` on `requirements-dev.txt` with CI's two exceptions | **Fails today**: 47 advisories (see finding 7) |

The baseline run overlapped benchmark load and the first source edits, so its
timings are not a performance reference. The post-fix full run is the
authoritative suite result and is recorded at the end of this file.

## Findings

Ordered by priority. 1–6 are fixed on this branch; 7–12 are open.

### 1. Post-login open redirect — fixed, tested

`app.py:_validated_next_url` accepted any `next` value with one leading slash.
Browsers drop tabs and line breaks from a `Location`, so `next=/%09/host`
passed validation and the server answered `Location: //host`.

- Reproduction (synthetic instance): `POST /login` with `next="/\t/evil.example"`
  returned `302 Location: //evil.example`. `GET /login?next=…` carried the same
  value into the form's hidden field, so a crafted sign-in link was sufficient.
- Impact: a legitimate sign-in on the real toolkit ends on an attacker's page.
  No session or credential disclosure by itself. Confidence: high.
- Fix: `local_redirects.local_redirect_target` rejects control characters,
  backslashes, scheme and authority. Used by sign-in, dashboard reset actions
  and investigation forms. `tests/test_local_redirects.py`: 3 cases failed
  before, 22 pass after.

### 2. The test suite opened the checkout's live `instance/` — fixed, tested

`tests/test_tool_registry.py` and `tests/test_audit_policy.py` called
`create_app()` with no path. Flask's default is `<checkout>/instance`, the same
directory `./twn` uses for live data.

- Evidence: after the baseline run the worktree contained a new `instance/`
  with 18 entries (databases, migration ledger, secret key).
- Impact: running the documented `pytest -q` in an installed checkout runs
  schema migrations against, and opens every store in, production data. On this
  host the checkout is the installation. Confidence: high.
- Fix: both tests use a temporary instance; `tests/conftest.py` makes any
  `create_app()` without an explicit path fail.

### 3. Dead-end error pages — fixed, tested and observed

No error handlers existed. 148 `abort`/403 call sites, every unknown URL and
every POST-only address opened in a tab produced an unstyled server page with no
navigation. Observed as a restricted operator: following a link to a tool
outside the account's access showed one line of plain text.

- Fix: one handler renders `templates/error.html` inside the normal layout for
  browser navigations only (`Sec-Fetch-Mode: navigate`, or an explicit
  `text/html` Accept when no fetch metadata is sent). Script, form and API
  requests keep their previous bodies and status codes. The 500 page never
  includes exception text.
- Verified in the browser at 1280×800 and 375×812 as administrator and as an
  operator with no tools: sidebar present, no horizontal overflow, link returns
  to the dashboard. Not checked: all six palettes, both densities, text scaling,
  and the page as rendered through an Agent tunnel.

### 4. Certificate Automation page started Certbot on every view — fixed, measured

`AcmeDnsManager.runtime()` ran `certbot --version` synchronously per request.

| | Median page time, synthetic instance |
|---|---|
| Before | 420 ms (382–403 ms inside the subprocess) |
| After | 7 ms |

On slower hardware the probe could reach its 3 s timeout and report Certbot as
unavailable (estimate, not measured). The result is now remembered for the
exact executable (path, inode, mtime, size); failures are retried after 60 s.
A subprocess trace of all 74 parameterless GET pages found no other page that
spends more than 10 ms in child processes.

### 5. World-readable logs and transfer history — fixed, tested

The web process starts with the caller's umask while the workers set 077. On
the live instance these were mode 0644 inside a 0775 `instance/`:
`twn-toolkit-access.log`, `twn-toolkit-error.log`, `twn-toolkit-restart.log`,
`ssh_transfer_history.sqlite3`. They hold request paths, client addresses,
usernames and transferred file names. All other databases, keys and archives
were already owner-only.

- Fix: the supervisor's log visit corrects the mode through its verified
  descriptor; the SFTP/SCP history store restricts its file on every use, as
  the TFTP store already did.
- Takes effect on the live instance only after the code is deployed and the
  supervisor restarted. **Not fixed:** `instance/` itself stays 0775 (item 10).

### 6. No Content-Security-Policy — partly fixed, tested and observed

Added `object-src 'none'; base-uri 'self'; frame-ancestors 'none';
form-action 'self'`. Sign-in and six representative pages loaded in the browser
with no policy violations. Script and style sources are not restricted: 12
inline script blocks and 34 inline event handlers remain (item 11).

### 7. Dependency audit gate now fails — open, blocks every merge

`pip-audit` against the current locks, with CI's two documented exceptions,
reports 47 advisories published since v0.27.0:

| Package (locked) | Advisories | Fixed in | Pulled in by |
|---|---|---|---|
| pillow 12.3.0 | 40 | 13.0.0 | reportlab (PDF case reports) |
| pyasn1 0.6.4 | 4 | 0.6.5 | pysnmp |
| certifi 2026.7.22 | 2 | 2026.10.18 | requests |
| dnspython 2.7.0 | 1 | 2.9.0 | direct pin |

- Impact: the **Dependency audit** job will fail on the next push, including
  for PR 313 if re-run. Reachability of the individual advisories was not
  analysed; Pillow is reached only through report generation.
- Not done here: `docs/dependency-locks.md` requires regenerating with
  uv 0.8.15 (not installed on this host) and cross-platform CI. Pillow 12→13 is
  a major version.
- Acceptance: locks regenerated with recorded provenance; `pip-audit` clean
  with unchanged exceptions; full suite on all CI platforms; one PDF case report
  generated and opened.

### 8. Agent certificates expire after 30 days with no renewal in this head — open, inferred

`distributed_pki.CLIENT_CERTIFICATE_DAYS = 30`; this head contains no renewal
path. The design notes in the interaction audit are still accurate as "not
implemented" here. Two unmerged implementations exist: PR 313 (3 files, +225,
renew-before-expiry) and local `codex/agent-lifecycle` (renewal, expired
recovery with explicit approval, generation fencing). They overlap and neither
was reviewed line by line in this pass.

- Decision needed: which of the two is the intended line, before either merges.
- Acceptance stays as the interaction audit lists it (near expiry, offline past
  expiry, revoke → remove → re-enrol with the same key, replay, listener
  rotation). Trust checks were not weakened and no enrollment was exercised.

### 9. Live service runs an unreleased branch from the working checkout — open, operational

The installation serves whatever the primary checkout has checked out.
Templates and static files are read per request, so switching branches or
editing files there changes the running application without a restart, while
Python code stays at the version loaded at start. Recommendation: keep the
installation on a tagged release in its own directory and do development in
worktrees. No change made.

### 10. `instance/` directory is group- and world-traversable — open

Mode 0775 on the live instance (`twn` uses `mkdir -p` under the caller's umask;
`service_cli` creates it 0700 on another path). With item 5 fixed, the files
inside are owner-only, so exposure is limited to file names and sizes.
Tightening it belongs in the launcher, which carries documented platform
fixes; it needs Linux and macOS service acceptance rather than a blind edit.

### 11. Full script Content-Security-Policy — open, medium effort

Move 12 inline script blocks and 34 inline handlers into static files, then add
`script-src 'self'`. Acceptance: no inline script in templates (lint test), the
header present, and a browser pass over every tool page with no violations.

### 12. Measured, no change recommended now

- **Authentication file parsing.** `auth.json` is parsed 4 times per trivial
  authenticated request and more per page. Measured cost at 1 user: below
  1 ms total. At 500 synthetic users: `/session/activity` 0.9 → 6.7 ms and
  pages +12–20 ms. Not worth caching at realistic local-first user counts.
- **Distributed queue journal mode.** `distributed_jobs.sqlite3` uses the
  rollback journal while most stores use WAL. One full tunnel cycle
  (enqueue → claim → start → complete with a 60 kB body), one claimant:

  | Concurrent requesters | Rollback p50 / p95 | WAL p50 / p95 | Throughput rollback / WAL |
  |---|---|---|---|
  | 1 | 56 / 109 ms | 58 / 110 ms | 15 / 14 per s |
  | 8 | 120 / 223 ms | 111 / 166 ms | 51 / 66 per s |
  | 32 | 628 / 758 ms | 460 / 558 ms | 49 / 67 per s |

  No lock errors in either mode. The single-request floor is the two 50 ms
  polling sleeps, not SQLite. Numbers were taken on NVMe while the test suite
  was running, so treat them as relative. WAL would give roughly 30% at high
  concurrency; an adaptive first poll would cut the floor. Both touch the
  transaction boundary described in `agent-continuity.md` and should be a
  deliberate change with the queue's concurrency tests, not a drive-by.

## Coverage ledger

| Area | Status | Evidence / gap |
|---|---|---|
| Route authorization, restricted user | tested | All 74 parameterless GET routes as an operator with no tools: 63 × 403, the rest self-service or redirects. Parameterized and mutating routes rely on the registry contract test, not a sweep. |
| CSRF and origin checks | inferred | `SameSite=Strict`, `Sec-Fetch-Site`/Origin comparison, WebSocket origin check read; existing tests not extended. |
| Redirect targets | tested | Finding 1. |
| Command execution sinks | inferred | No `shell=True`, `os.system`, `eval`, `pickle` or YAML loading in the package. |
| Archive handling | inferred | No `extractall`; ZIP use is write-side plus bounded readers. Import bounds not re-tested. |
| File downloads | inferred | All 13 `send_file` call sites force attachment disposition. |
| TLS verification | inferred | Disabled only in certificate inspection tools, the SMTP test tool and first-contact pairing, which authenticates by code comparison. |
| Instance file permissions | tested | Finding 5; fixture and live modes listed. |
| Dependency advisories | tested | Finding 7. |
| Upgrade integrity | inferred | Bundle checked against a SHA-256 asset from the same release; no signature. Residual risk, not analysed further. |
| Distributed queue under load | measured | Item 12. Lease expiry, redelivery and fencing not re-tested. |
| Certificate lifecycle | inferred | Finding 8. |
| Mainframe Synced Objects conflicts | unverified | Documentation read only. |
| Automation scheduler duplicate execution and crash recovery | unverified | |
| Page latency, empty instance | measured | All parameterless GET pages; slowest after the fix is under 40 ms warm. |
| Scale: hosts, jobs, rules, histories, evidence | unverified | Only user count and queue concurrency were varied. Earlier bounded-pagination work was not re-measured. |
| Concurrent terminal sessions | unverified | |
| Browser journeys | observed | Sign-in, restricted dashboard, denied tool, missing page, administrator dashboard, six tool pages for console errors. No form submissions that execute tools. |
| Keyboard, focus, themes, density, text scaling | unverified | In this pass. |
| Agent-delegated pages, offline Agents | unverified | No Mainframe or Agent was configured. |
| Installer, systemd/launchd, upgrade and rollback | unverified | Shell syntax only. |
| macOS, Arch, Raspberry Pi | unverified | Linux x86-64, Python 3.12 only. |
| Native helpers | unverified | |

## Backlog

| # | Item | Effort | Depends on | Acceptance |
|---|---|---|---|---|
| 1 | Regenerate dependency locks (finding 7) | S–M | uv 0.8.15 | Audit clean, full CI, PDF report opens |
| 2 | Choose and land one certificate lifecycle line (finding 8) | L | Owner decision, item 1 | Interaction-audit certificate test list |
| 3 | Separate the installation from the working checkout (finding 9) | S, operational | Operator | Service runs a tagged tree; restart planned |
| 4 | Owner-only `instance/` in the launcher (item 10) | S + acceptance | Linux and macOS service tests | New and existing instances 0700; services start |
| 5 | Script CSP (item 11) | M | — | No inline script; no violations in browser pass |
| 6 | Error page palette, density, text-scale and Agent-tunnel pass | S | — | Matrix recorded in the interaction audit |
| 7 | Queue WAL and adaptive tunnel polling (item 12) | M | Queue concurrency tests | Same measurements repeated on idle host; no claim regressions |
| 8 | Scale measurements for hosts, jobs, rules, evidence | M | Synthetic generators | Measured limits at three sizes per store |

## Changes

The review ran against the unpublished local head. The six fixes were then
replayed without conflict onto published `main` (`3ddaaee`) as branch
`claude/audit-fixes-on-main` so they can be reviewed without the 43 unreleased
commits; the same commits also exist on local `claude/repo-audit-2026-11`.

1. Reject post-login redirect targets browsers resolve off-origin
2. Keep the test suite out of the checkout's live instance directory
3. Show a navigable page when a browser lands on a denied or missing address
4. Probe the Certbot version once per executable instead of per page view
5. Restrict operational logs and SSH transfer history to the toolkit account
6. Send baseline Content-Security-Policy containment directives

CONTRIBUTING asks for one concern per branch; these are separate commits so
they can be split. None can merge until the dependency audit gate (finding 7)
is green. References below to "the interaction audit" are to documents that
exist only in the unpublished local stack.

## Running the suite on this host

Use a short `TMPDIR`: one Raspberry Pi broker test binds a Unix socket under
it, and a path over about 100 bytes fails with `AF_UNIX path too long`.

## Post-fix validation

Full suite at local `902fa2b` (the six code commits on the unpublished head), fresh hash-locked environment, Python 3.12, Linux x86-64, short `TMPDIR`:
**2,630 passed, 5 skipped, 483 subtests passed in 789.67 s; 0 failed.** That is
42 more passing tests than the baseline: 41 added here plus the one baseline
failure that was environmental. The run created no `instance/` directory in the
checkout. Lock provenance, Python compilation, shell syntax, whitespace and
release-bundle construction also passed. The bundle is validation only.

Not run: GitHub Actions (nothing was pushed), macOS, Arch, Python 3.10 and
3.13, and any check against real devices, Agents or the live service.
