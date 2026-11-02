# API Tester: compose, send once, inspect and deliberately resend

Base 63c4e6b preserves the prior SNMP/RADIUS candidate and all preceding interaction work. This branch is a bounded API Tester journey, not a saved-profile feature or a whole-application completion claim. No live service, webhook, credential, trust or device changes were made.

## Verified starting behavior and correction

An isolated baseline with a mocked sender reproduced two identical POST submissions invoking the sender twice. Both responses rendered directly from POST; the composer lacked `data-unsaved-form`. This establishes the missing server admission fence and source-supported refresh/resubmission risk; it does not claim a browser silently replayed a write.

**Correction to the earlier source assessment:** the shared runbar's “Send again” was a real submit button bound to the composer, not merely a settings opener. The prior temporary assessment has an explicit erratum. The replacement has one “Edit & send again” opener and one “Send request once” within settings.

## Implemented task

The composer uses the shared memory-only unsaved guard. Sending is not saving: even an acknowledged send leaves a navigation warning for the transient composer. Nothing writes request headers/body or response contents to browser storage. Changing a write request clears consent; every send is explicit, and closing settings cannot retract a remote operation.

A small SQLite admission ledger contains only random nonce/owner/state/timestamps and allowlisted numeric/boolean outcome metadata. Atomic claim requires an existing unexpired owner-scoped issued nonce. Concurrent connections/processes admit it once; expired, consumed, foreign or pruned values cannot recreate work. There is no queue, dispatcher or recovery retry. Limits are 128 unused forms per owner, 4096 total rows, 15-minute unused expiry and 24-hour terminal retention. After a process interruption, admitted attempts become unconfirmed after 35 seconds without executing again. Late completion cannot upgrade an already stale receipt.

Local syntax, numeric timeout and write consent validate before claim. Native admitted POST redirects with 303 to an owner/tool-permission-protected metadata-only GET receipt. Full request/response contents deliberately do not survive that redirect; this tradeoff preserves the existing never-saved promise. An asynchronous send keeps the composer and response in the current page only and sets a safe GET receipt URL before waiting. Refresh/return never sends. Receipt text remains conservative for issued/admitted/unconfirmed states because a delayed request may still arrive.

The client locks repeated submission while pending and bounds send/preparation waits. It never retries a POST. Lost, redirected, malformed or mismatched acknowledgments keep the draft and explain remote uncertainty; read-only preparation is separate from the next explicit send. Known local validation stays correctable. Access loss gives sign-in/access guidance. Receipt capacity does not discard a confirmed transient response. HTTP 4xx/5xx responses remain confirmed transport responses with error styling, not transport uncertainty.

Results identify the **submitted** method/origin. Newer pending edits stay visible and unfocused; “View previous response” is explicit. Response text, headers and remote reason use text nodes; existing resolved addresses, error pill, bounded header table, redirect/truncation notices and response body remain available. Request URL/header values are excluded from the JSON result projection. Raw transport exceptions, remote reason, invalid method and invalid timeout values are excluded from durable audit/journal projections.

## Evidence and limits

- Isolated backend tests cover process/thread atomic claim, restart/stale state, owner isolation, expiry/pruning/capacity, native 303/GET replay safety, validation-before-claim, write consent, real tool grants/revocation, transport exceptions, optional recording failure, privacy markers and confirmed HTTP errors.
- No-bind fixture tests verify actual Flask status/MIME, send counts and receipt state for normal, access-denied, HTML/JSON lost acknowledgments, wrong token and sender failure modes. Five external HTTP/process/socket boundaries fail closed. Fixture startup initially collided with the existing index endpoint; the renamed endpoint was tested before any listener was launched. No product failure was inferred from that fixture error.
- The shipped client executes in host V8 against a synthetic DOM/fetch model. Nine groups cover repeated submission, pending receipt history, escaped rendering, submitted identity, newer-edit layout/focus, malformed ACKs, uncertainty/timeout, read-only preparation, capacity/access and consent. URL parsing in that model is a limited interface for fixed synthetic origins, not browser interoperability proof. Node wrappers may skip separately when Node is absent.
- Actual browser checks remain **unverified**. Supported browser input is blocked by a prior synthetic native confirmation: input/dialog/close operations timed out, no dialog handle was exposed and the tab remained open. No bypass, retry of blocked input, or product change to accommodate the harness was attempted. Keyboard, native refresh/back, responsive layout and actual modal focus need supported-browser follow-up after resolution.
- No external API calls, real credentials, workers, agents, schedulers, live instance changes or publication. Real TLS/redirect/transport interoperability, browser multi-tab behavior and Agent/delegation remain unverified. Other tools' workflows and load performance are outside this batch.
