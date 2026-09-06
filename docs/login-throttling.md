# Sign-in rate limits and recovery

Public sign-in requests reserve capacity before password verification. Counters
are shared by all web workers using the same instance directory. Successful and
failed attempts both consume capacity; signing in does not reset shared limits.

The centralized code settings in twn_toolkit/login_throttle.py are:

| Setting | Default | Scope |
| --- | --- | --- |
| WINDOW_SECONDS | 60 seconds | Counter lifetime from its first admitted attempt |
| USERNAME_ATTEMPTS | 10 | Case-insensitive username, across source addresses |
| SOURCE_ATTEMPTS | 20 | IPv4 address or IPv6 /64, across usernames |
| INSTANCE_ATTEMPTS | 120 | All sign-in attempts on the instance |
| MAX_PASSWORD_CHECKS | 4 | Simultaneous password verifications across workers |
| MAX_BUCKETS | 4,096 | Retained counter rows; active rows are never evicted to admit new identities |
| LOGIN_BODY_BYTES | 16 KiB | Entire login request body |
| DATABASE_WAIT_SECONDS | 0.25 seconds | Maximum limiter database lock wait |
| AUDIT_INTERVAL_SECONDS | 60 seconds | Minimum interval between rate-limit audit events |

These are code tuning points, not Settings UI controls. Apply consistent values
to all workers and restart them after changing policy. A source limit may cover
multiple people sharing a NAT or proxy. Account limits prevent rotating source
addresses from avoiding the username budget. Unknown and disabled usernames
follow the same limits and perform a dummy password verification. Usernames over
64 characters or passwords over 1,024 characters are rejected before hashing.

## What a user sees

Exhausted capacity returns HTTP 429 with a Retry-After header and a retry message.
There is no permanent account-disable action. Rejected attempts do not extend
counter expiry; after the stated interval, another attempt can be admitted.
A sustained attack can consume newly available capacity, so legitimate sign-ins
may still be delayed. Existing authenticated sessions are unaffected.

A full password-check pool returns a short retry response without waiting for a
slot. OS locks release slots when a verifier returns, raises, or its worker exits.
A limiter storage error returns HTTP 503 and skips password verification.

## Client addresses and proxies

The limiter uses the WSGI connection address (request.remote_addr), matching the
toolkit's existing trusted-host checks. It does not independently trust
X-Forwarded-For or Forwarded headers. IPv4-mapped IPv6 addresses share their IPv4
bucket; native IPv6 addresses are grouped by /64 to limit address rotation.

A reverse proxy therefore normally shares one source bucket. If a deployment
rewrites the WSGI address, that middleware must accept forwarded information only
from its configured trusted proxies. Do not trust arbitrary request headers to
obtain separate limits. Trusted-host restrictions and upstream controls remain
useful alongside application throttling.

## Local recovery and visibility

From the toolkit directory, using the toolkit's service account and Python
environment, inspect counters:

~~~sh
.venv/bin/python -m flask --app twn_toolkit login-throttle
~~~

Clear temporary counters without deleting users, changing passwords, ending
sessions, or restarting the service:

~~~sh
.venv/bin/python -m flask --app twn_toolkit login-throttle --reset
~~~

For a custom instance directory, select the same instance in the Flask app
factory, for example --app 'twn_toolkit:create_app("/path/to/instance")'.

The command reports active counter rows and rate-rejected requests since reset.
That count excludes password-slot saturation and storage failures, which are
visible as HTTP 429/503 responses. Authentication audit events summarize rate
limiting at most once per configured interval across workers.

The owner-only login_throttle.sqlite3 stores HMAC identifiers, counters, expiry
times, and aggregate rejection statistics. It stores no plaintext usernames,
addresses, or passwords. Expired identifiers are reclaimed on the next admission
check. Do not delete lock files while workers run; use the counter-reset command.

The design balances throttling and lockout risks described in the
[OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling).
