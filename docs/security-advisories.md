# Security Advisories

The release CI audits every pinned runtime and test dependency with `pip-audit`. A
release must either use a fixed dependency or document a narrowly applicable
exception with an active mitigation and a removal condition.

## Reviewed exceptions for 0.10.x

### Paramiko — CVE-2026-44405 / PYSEC-2026-2858

Paramiko through 4.0.0 permits SHA-1 RSA signatures and did not have a fixed
PyPI release when the 0.10.x line was prepared. The toolkit disables `ssh-rsa` for both
host-key and public-key negotiation in every Paramiko client and server path.

An operator who must connect to a legacy appliance that supports no RSA-SHA2,
ECDSA, or Ed25519 option can explicitly enable legacy SSH compatibility for one
Bulk SSH or Bulk Transfer run, or in the saved settings for an SSH/SFTP/SCP
automation or the managed SFTP/SCP service. These controls pass the exception
through the shared policy to that operation only and are audited without secrets.
Saved exceptions remain enabled until disabled. The
`TWN_ALLOW_LEGACY_SSH_RSA=true` environment variable remains an emergency global
override affecting every SSH path. Either form weakens SSH authentication and
must be limited to trusted legacy devices on controlled networks. Remove this
exception and the CI allow-list entry when Paramiko publishes a release containing
upstream commit `a448945` or a superseding fix.

### Scapy — GHSA-cq46-m9x9-j8w2

Scapy 2.6.1 can execute code when a user explicitly loads an untrusted pickled
interactive session through Scapy's session loader. The toolkit does not start
the Scapy shell, accept Scapy session files, call `load_session`, or expose the
session configuration. It imports only the packet-sending configuration needed
for Packet Replay. Do not add session loading to the application. Remove this
exception and the CI allow-list entry when Scapy 2.7.0 or another fixed release
is available for all supported Python versions.

## Python 3.10 exception retired

The Python 3.10-only Pillow 12.3.0 and dnspython 2.7.0 exception introduced on
2026-11-11 is retired by the Python 3.11 minimum. Supported installations now
select Pillow 13.0.0 and dnspython 2.9.2 unconditionally. The vulnerable pins
and their Python-version splits are removed from both hash locks.

Older releases still running Python 3.10 retain their old dependencies and
exposure; this policy change does not patch those installations. Follow the
[Python migration guide](python-upgrade.md) before updating. CI audits both
Python 3.11 and 3.13 so the minimum supported branch is covered.

## Release review

For every release:

1. Run the dependency-audit CI job against the exact pinned requirements.
2. Recheck whether an ignored advisory now has a fixed compatible release.
3. Confirm the mitigated feature boundary still matches the implementation.
4. Treat any new advisory or expanded exposure as a release blocker until it is
   fixed or reviewed and documented here.

## Pending review — 2026-11-11

A local `pip-audit` run against the 0.27.0 locks, with the two exceptions above,
reported new advisories for Pillow 12.3.0 (via ReportLab), pyasn1 0.6.4 (via
PySNMP), certifi 2026.7.22 and dnspython 2.7.0. None has been reviewed or
excepted. The dependency-audit CI job fails until the locks are regenerated or
each advisory is reviewed here. Details: [`system-audit-2026-11.md`](system-audit-2026-11.md).
