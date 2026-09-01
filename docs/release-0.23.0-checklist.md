# v0.23.0 release checklist

## Scope

- [x] Add standalone, Mainframe, and agent coordination roles while retaining
  complete local toolkit operation and standalone as the default.
- [x] Add administrator-approved enrollment, private-CA certificate issuance,
  mutual-TLS reconnect, durable denial and revocation, and guarded removal of
  revoked inventory records.
- [x] Add per-user instance selection, context-aware navigation, per-agent
  appearance, native remote-interface tunneling, concurrent interactive lanes,
  and separate durable remote jobs.
- [x] Add explicit listener and advertised certificate identities, closed-by-
  default timed enrollment, durable throttling, bounded listener concurrency,
  and an optional certificate-verified fallback Mainframe URL.

## Platform and compatibility boundary

- [x] Add no Python dependency and retain the normal `v0.9.0` minimum direct-
  upgrade boundary; no stepped release is required.
- [x] Create new distributed settings, PKI, trust, job, throttle, and runtime
  stores without modifying portable saved-profile formats. Automatically add
  per-user execution-context and per-instance appearance fields.
- [x] Require a toolkit restart after changing the distributed role or listener
  identities, but require no service reinstall from v0.22.2 on Linux, macOS, or
  Raspberry Pi installations.
- [x] Keep agents outbound-only and preserve local web access. Treat Mainframe
  CA material as instance identity preserved by complete recovery points and
  intentionally excluded from portable configuration exports.
- [x] Document current limits: interactive request and response bodies are
  bounded to 192 KiB; large streaming bodies and WebSockets require the future
  multiplexed transport; CA rotation and proactive 30-day client-certificate
  renewal remain future lifecycle work.

## Local and live validation

- [x] Pass the focused version, Help/dashboard, settings, enrollment, PKI,
  transport, capability, and distributed-job suite: 53 tests passed.
- [x] Pass the complete v0.23.0 release-preparation suite: 934 tests passed, 1
  expected skip, and 339 subtests passed.
- [x] Run `pip-audit==2.10.1` with only the repository's two documented
  advisory exceptions: no known vulnerabilities found.
- [x] Build and validate the v0.23.0 upgrade bundle with 445 archive entries,
  444 manifest payload files, the `v0.9.0` minimum upgrade boundary, and a
  matching SHA-256 checksum sidecar.
- [x] Validate a live Linux Mainframe and Raspberry Pi agent across enrollment,
  matching pairing codes, certificate delivery, mutual-TLS heartbeat,
  revocation, reconnect, native remote UI navigation, Remote Terminal, and file
  upload/download workflows.

## Pull-request and merged-main gates

- [x] Pass distributed Mainframe feature PR #163 in CI run `33455324791`,
  squash-merge it as `0e8b4d6aba8601fdce55c7e3aa7a40ca7ddb799e`, and pass
  merged-main CI run `33455600422` on Ubuntu Python 3.10/3.13 and macOS Python
  3.13, including repository checks and dependency audit.
- [ ] Pass the v0.23.0 release-preparation pull request and merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.23.0` tag only after every validation
  and merged-main item above is complete.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both `twn-toolkit-v0.23.0.zip` and
  `twn-toolkit-v0.23.0.zip.sha256` before announcing upgrade availability.

Stop before tagging unless every validation and merged-main item above is
complete.
