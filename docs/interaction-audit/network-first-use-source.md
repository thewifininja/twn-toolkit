# Network first-use source and isolated validation audit

Audited baseline: `88c7c7d4da338340ea58e94f813982916c6db8d9`. This read-only audit made no product changes or live/device requests. It covers four tools, not the whole application.

Current follow-up: [network failure continuity](network-failure-continuity.md) records the bounded DNS/NTP/RADIUS fixes and newer browser evidence. This document retains the historical source/isolated evidence; it does not establish current SNMP completion.

## Prioritized findings

1. **NTP remembered-profile overwrite — source inferred.** `static/ntp-test.js` restores the remembered profile and dispatches change, whose handler replaces targets. An isolated invalid POST retained edited targets alongside the remembered profile on the server; actual browser execution of the overwrite was **not** performed. Next: reproduce in a supported browser, then restore remembered profiles only into an empty fresh form rather than posted/draft targets.
2. **DNS errors need hover; unavailable latency renders “None ms” — synthetic HTML reproduced.** `templates/tools/dns_response.html` puts the reason in an unfocusable span title and formats null latency numerically. A seeded retained timeout row reproduced this markup; visible text lacked the reason, while CSV retained it. Next: show actionable error details with keyboard access and a precise unavailable-time label.
3. **RADIUS invalid run error can be in a hidden panel — synthetic HTML reproduced.** `templates/tools/radius_test.html` defaults to Profiles when prerequisites are missing, but renders the run error in a hidden workflow pane. Remembered tab selection may mask it; computed browser visibility was **not** tested. Next: force the error-containing pane and link to the missing prerequisite.
4. **SNMP prerequisite path — source observation.** Empty-account Tests says to create a host profile rather than guiding credential → host setup. Default OID collections exist. Next: test complete first-use setup and return, not an OID-empty-state redesign.

## Evidence and limits

| Tool | Isolated evidence | Unverified |
| --- | --- | --- |
| DNS | GET; invalid target/resolver/type/load-consent/duration; seeded retained timeout HTML/CSV; foreign result 404 and unfinished CSV 409 | Actual resolver/load/TCP fallback, browser polling/cancel, keyboard and responsive layout |
| NTP | GET; missing targets/invalid numeric POST; posted target preservation with remembered profile | JavaScript overwrite, UDP measurements, repeat/back/refresh; no dedicated result export identified |
| SNMP | GET; stale/missing host POST; invalid profile JSON400; synthetic secret not echoed | Actual v2/v3 queries/walk/monitor, auth/privacy/vendor interoperability, layout/keyboard; no dedicated result export identified |
| RADIUS | GET; stale/missing profiles, EAP invalid POST, hidden error HTML; invalid profile JSON400; synthetic secrets not echoed | Actual Accept/Reject/timeout, PAP/CHAP and retransmission, layout/keyboard; EAP intentionally disabled; no dedicated result export identified |

All four were tested for administrator, granted member and denied member on GET, invalid run POST and invalid profile POST. This verifies these tool gates, not exhaustive profile ownership/editing permissions. NTP/SNMP/RADIUS synchronous refresh/back/resubmission behavior was source traced, not browser tested.

The independent audit reported **37 isolated tests passed**. Seven fail-closed mocks asserted zero calls to DNS matrix/load runners, NTP, SNMP and RADIUS runners, `socket.create_connection` and `socket.getaddrinfo`. All POSTs were deliberately invalid or denied; completed DNS results were seeded into temporary storage without a worker. Accounts/profiles/secrets were synthetic; no production files/configuration were read. These checks were performed by the audit worker, not rerun as part of this documentation update. No real-device or exhaustive whole-app coverage is claimed.
