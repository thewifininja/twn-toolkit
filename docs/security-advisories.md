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

## Reviewed exception for Python 3.10 installations (2026-11-11)

Pillow 13.0.0 and dnspython 2.9.0 are the first releases that fix the advisories
below, and both require Python 3.11 or newer. No fixed release exists for Python
3.10. The locks therefore select the fixed releases on Python 3.11 and newer and
keep the last compatible releases, with these known advisories, on Python 3.10
only. Installations on Python 3.11 or newer are not affected by this exception.

The dependency-audit CI job runs on Python 3.13 and evaluates only that branch of
the lock, so it reports nothing for the Python 3.10 pins and needs no allow-list
entry for them. It also cannot detect new advisories against those pins; recheck
them by hand during the release review until this exception is removed.

### Pillow 12.3.0 on Python 3.10

Forty advisories, all fixed in 13.0.0: CVE-2026-96638, CVE-2026-96640,
CVE-2026-96778, CVE-2026-112390, CVE-2026-112391, CVE-2026-112393,
CVE-2026-112395, CVE-2026-112399, CVE-2026-112400, CVE-2026-112401,
CVE-2026-112404, CVE-2026-112406, CVE-2026-112891 through CVE-2026-112895,
CVE-2026-112897, CVE-2026-112899, CVE-2026-112900, GHSA-78g4-xqwv-q3g8,
PYSEC-2026-4326 through PYSEC-2026-4343, and PYSEC-2026-4363.

Each one requires Pillow to decode, transform, or encode attacker-influenced image
or PDF data. Pillow is installed only as a ReportLab dependency. The toolkit does
not import Pillow, and the case-report export builds its PDF from text and tables
only: it places no images and never opens case evidence or any other uploaded file
with Pillow. Do not add image decoding, thumbnailing, or image embedding of
operator- or device-supplied content while this exception stands.

### dnspython 2.7.0 on Python 3.10 — CVE-2026-114605 / GHSA-45c3-73f7-pv4m

A crafted DNS message can make name decompression use excessive CPU. The toolkit
uses dnspython only as a resolver client: DNS diagnostics query the servers an
operator selects, and ACME DNS validation queries the system resolver and the
authoritative servers of the operator's zone. It never parses DNS messages from
files or inbound requests. A hostile or compromised server among those can slow
the worker handling that lookup; it cannot reach other data. On Python 3.10,
point DNS diagnostics only at servers you would otherwise trust to answer.

Remove this exception and the `python_version` splits in `requirements.in` when
Python 3.10 support is dropped, or when Pillow and dnspython publish fixed
releases that install on Python 3.10.

## Release review

For every release:

1. Run the dependency-audit CI job against the exact pinned requirements.
2. Recheck whether an ignored advisory now has a fixed compatible release.
3. Confirm the mitigated feature boundary still matches the implementation.
4. Treat any new advisory or expanded exposure as a release blocker until it is
   fixed or reviewed and documented here.
