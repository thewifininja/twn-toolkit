# v0.18.1 release checklist

## Scope

- [x] Restore HTTPS release discovery for launchd-managed macOS workers using
  the protected TCP relay.
- [x] Ignore only `TCP_NODELAY` on an adopted local relay endpoint and preserve
  normal socket-option behavior everywhere else.
- [x] Apply `TCP_NODELAY` to the native helper's actual remote TCP socket.
- [x] Rebuild and validate the checked-in universal arm64/x86_64 macOS helper.

## Compatibility

- [x] No database, profile, dependency, service-topology, property-list, or
  backup-format change is required.
- [x] The Python compatibility repair works with the helper installed by
  v0.17.0 or v0.18.0; a service reinstall is not required to restore HTTPS.
- [x] `sudo ./twn service install` after the code upgrade refreshes the native
  helper and applies `TCP_NODELAY` at the remote side of the relay.
- [x] Manual startup, Linux, non-brokered sockets, and non-TCP socket options
  retain their existing behavior.

## Validation

- [x] Exercise a production-shaped `HTTPSConnection` through an AF_UNIX relay
  descriptor on Python 3.12, 3.13, and 3.14.
- [x] Pass the real loopback descriptor-adoption regression and native
  bidirectional/half-close relay harness on macOS.
- [x] Run the complete local test suite from the release-preparation source:
  655 passed, 7 skipped, and 241 subtests passed.
- [x] Pass shell syntax, Python source compilation, and the CI-pinned dependency
  audit: no known vulnerabilities found, with the two documented advisories
  ignored by policy.
- [x] Build and validate the exact v0.18.1 upgrade bundle and checksum: 351
  manifested files and a matching SHA-256 digest.
- [ ] Pass pull-request CI on Ubuntu Python 3.10/3.13 and macOS Python 3.13,
  including repository checks and the dependency audit.
- [ ] Squash-merge the approved pull request and pass merged-main CI.

## Publication gate

- [ ] Create and push the annotated `v0.18.1` tag only after the project owner
  approves publication from the merged commit.
- [ ] Confirm tag CI accepts the exact `APP_VERSION` match.
- [ ] Publish the GitHub release.
- [ ] Verify the published release contains both
  `twn-toolkit-v0.18.1.zip` and `twn-toolkit-v0.18.1.zip.sha256` before
  announcing in-app upgrade availability.

Stop before pushing, opening a pull request, merging, or tagging until the
validated branch is reviewed and the project owner requests those actions.
