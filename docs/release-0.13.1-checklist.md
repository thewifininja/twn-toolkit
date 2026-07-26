# v0.13.1 release checklist

## Guided ACME issuance

- [x] Certbot runs in a background worker with noninteractive manual-auth and
  cleanup hooks, pauses for each DNS challenge, and survives normal page
  navigation.
- [x] Requests support Let's Encrypt staging and production, multiple DNS names,
  wildcards, ECDSA P-256 or RSA 2048 keys, and explicit Subscriber Agreement
  acceptance.
- [x] Operators can copy each TXT name and value, check propagation, continue
  deliberately, cancel active work, reopen retained history, and download
  completed requests.
- [x] Sequential challenges sharing one `_acme-challenge` record retain every
  displayed TXT value until Certbot finishes.

## DNS propagation and cached answers

- [x] Propagation checks query the toolkit host's configured recursive resolver
  and report its resolver addresses, returned TXT values, TTL, and errors.
- [x] The same check discovers and directly queries public authoritative
  nameservers so a stale recursive-cache answer is visible without blocking an
  otherwise propagated challenge.
- [x] Authoritative readiness requires the expected value from every reachable
  authoritative server; disagreement remains visible and does not report ready.
- [x] Propagation status is advisory and offers an explicit continue action for
  operators who verified DNS another way.

## Certificate handling and interface

- [x] Certbot account data, request state, logs, and artifacts stay beneath
  owner-only instance storage; private keys use mode 0600.
- [x] Downloads provide leaf, chain, full-chain, private-key, and combined PEM
  files in a ZIP with private key entries marked owner-only.
- [x] ACME and Microsoft AD CS use focused tabs, certificate pages use the full
  application width, and the ACME request form reflows on narrow screens.
- [x] The tested ACME workflow is no longer labeled Beta; Microsoft AD CS keeps
  the Beta label and production-validation warning.
- [x] Certificate Automation reset removes ACME account data and artifacts, and
  profile backups continue to exclude certificate keys and request state.

## Product and compatibility

- [x] Certbot 5.7.0 is pinned with the toolkit dependencies and runs without
  `/etc/letsencrypt`, sudo, stored DNS-provider credentials, or broadened
  operating-system permissions.
- [x] v0.13.1 introduces no application-database or configuration migration;
  ACME state uses separate owner-only instance storage.
- [x] Generic DNS-01 renewal remains guided unless a DNS-provider API is
  configured separately with least-privilege credentials.
- [x] README, built-in Help, structured release notes, and tests describe the
  shipped workflow and its security boundaries.

## Release candidate gates

- [x] Build the v0.13.1 bundle from the release-preparation source and verify
  its internal manifest and external SHA-256 checksum.
- [x] Pass the complete local pytest suite and release-specific metadata tests.
- [ ] Pass pull-request CI on Ubuntu 3.10, Ubuntu 3.13, macOS 3.13, repository
  checks, and the dependency audit.
- [ ] After approval and squash merge, pass merged-main CI before creating the
  tag.
- [ ] Create and push the exact annotated `v0.13.1` tag only after every
  preceding gate is complete and the project owner explicitly approves it.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the release contains `twn-toolkit-v0.13.1.zip` and
  `twn-toolkit-v0.13.1.zip.sha256` before testing production discovery.
- [ ] From a production v0.13.0 installation, discover and install v0.13.1;
  verify recovery-point creation, web/scheduler/supervisor health, enabled
  services, certificate request history, audit history, and upgrade status
  after restart.
- [ ] Exercise rollback to the matched v0.13.0 recovery point and confirm the
  prior code and instance data return healthy.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
