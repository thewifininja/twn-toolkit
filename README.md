# The WiFi Ninja’s Toolkit

[![CI](https://github.com/thewifininja/twn-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/thewifininja/twn-toolkit/actions/workflows/ci.yml)

![The WiFi Ninja’s Toolkit dragon](twn_toolkit/static/brand/dragon-mark-128.png)

A local-first web toolkit for network diagnostics, repeatable Fortinet
administration, contained file transfer, and event-driven automation.

The toolkit runs on an operator workstation or trusted internal server. It
combines interactive troubleshooting tools with reusable profiles, scheduled
conditions, response pipelines, retained output, access control, and an
operational dashboard—without requiring a separate database server or cloud
service.

Current release: **v0.14.3**

> [!CAUTION]
> This software can send packets, test credentials, change managed devices,
> expose local file-transfer listeners, and run commands on remote systems. Use
> it only on infrastructure you are authorized to operate. It is not designed
> for direct exposure to the public internet.

## Navigation at a glance

- **Dashboard** — quick launch, workspace status, recent activity, and metrics
- **Fortinet Tools**
  - FortiGate, FortiAP, and FortiSwitch workflows
  - FortiAuthenticator workflows
- **Network Tools**
  - Addressing & Reachability
  - Multi-Host Tools
  - Services & Protocols
  - Traffic & Interfaces
- **Local Tools** — Datastore and managed File Transfers
- **Automation** — reusable Conditions, Actions, and Automations
- **Administration** — Settings, access, backups, operational limits, and
  System Diagnostics
- **Help** — searchable operator guidance and release notes

## What it includes

### Dashboard

The landing page is an operator workspace organized around three questions:
what can I run, what needs attention, and what happened recently. It provides:

- dashboard search plus quick launch cards drawn in personal Favorites order or
  from common diagnostics;
- at-a-glance live-monitoring, automation, and activity status;
- recent activity and a four-metric snapshot for the selected time range;
- an expandable full metrics view with administrator-managed widget visibility
  and drag-and-drop ordering; and
- an optional team activity view when more than one operator contributes.

Dashboard layout can be included in profile backups. Activity history and
counters are intentionally excluded.

### Fortinet Tools

#### FortiGate, FortiAP, and FortiSwitch

- Save and test multiple FortiGate profiles with API tokens, VDOM defaults,
  TLS policy, and bounded timeouts.
- Export managed AP, FortiSwitch, wireless-client, and switch-client inventory.
- Rename managed APs and FortiSwitches interactively or from CSV, with dry-run
  previews, explicit apply confirmation, partial-result summaries, and read-back
  verification.
- Reorder managed FortiSwitches by drag-and-drop or alphabetically, with an
  in-page preview and explicit confirmation.
- Find a normalized client MAC in local wireless association logs, combine log
  and live state, and collapse repeated visits into a clean AP history.

#### FortiAuthenticator

- Save and test multiple FortiAuthenticator profiles.
- Export paginated MAC-device and group-membership data.
- Preview and remove group memberships or delete MAC devices with overlap and
  impact warnings.

### Network Tools

The sidebar and Network Tools page use the same functional organization.

#### Addressing & Reachability

- **What’s My IP?** — show the client address used to reach the toolkit, the
  toolkit server’s public address, and the browser client’s public address.
- **Subnet Excluder** — subtract IPv4 or IPv6 CIDRs from one or more parent
  networks.
- **DNS Tester** — compare record values and response times across multiple
  resolvers, or run an authorization-gated, bounded load test with per-resolver
  throughput, success rate, and latency percentiles.
- **NTP Tester** — inspect offset, delay, jitter, stratum, reference identity,
  and synchronization health.
- **Path MTU Tester** — find the largest unfragmented IPv4 or IPv6 ICMP packet
  that reaches a target.
- **Traceroute** — run UDP or ICMP traces for multiple destinations with live
  graphical hops and text output.

#### Multi-Host Tools

- **Multi-Host Ping** — graph reachability, latency, and loss for a validated
  target snapshot; update targets without discarding unchanged history.
  Persistent runs continue through normal toolkit navigation and can be
  minimized to the collapsed-by-default Live tools footer dock, renamed in
  place, then restored with retained history by selecting the session card.
  A
  working optional `fping` system command enables batched high-capacity rounds
  and raises the target limit from 100 to 250. Without it, the standard system
  `ping` compatibility engine remains available. Multi-Ping exposes separate
  round-interval and per-target probe-timeout controls; accelerated mode accepts
  sub-second timeouts for dense groups of known-local targets.
- **Multi-SSH** — build prompt-aware concurrent runs in one spreadsheet-style
  target table, with a Raw Matrix editor for CSV-style pasting and a compact
  importer for friendly host lists and inclusive IPv4/IPv6 ranges. Substitute
  literal `{{ variable }}` values into reusable Stored Commandlets; the fixed
  `Host` column maps directly to `{{ host }}`, and older `IP/FQDN` headings
  remain accepted when importing saved matrices. Fleet runs support up to
  5,000 targets, submitted in batches of 50 with at most 10 simultaneous SSH
  connections and a bounded aggregate output budget. Commandlets can
  optionally retain their target matrix and per-host values, while credentials
  remain per-run only. Signed previews show every rendered command before
  execution.
- **Multi-Transfer** — fetch files concurrently over SFTP, SCP, or FTP into the
  Datastore or a one-shot ZIP, using collision-safe filename templates and the
  same explicit legacy SSH exception for SFTP/SCP.
- **TCP Port Scanner** — check individual ports or ranges across authorized
  hosts.

#### Services & Protocols

- **RADIUS Authentication Test** — compare PAP and CHAP results and returned
  attributes; optional `eapol_test` support adds PEAP/MSCHAPv2 and EAP-TLS.
- **Certificate Chain Inspector** — inspect the exact TLS chain presented by a
  server and validate dates, hostname, order, intermediates, and local trust.
- **Certificate Automation** — use a guided Certbot DNS-01 workflow for
  Let's Encrypt certificates, or enroll and rotate certificates through reusable
  Microsoft AD CS Web Enrollment profiles (Beta). The ACME wizard runs in the
  background, waits for each TXT record, compares the toolkit resolver with
  authoritative DNS during propagation checks, and provides a
  ready-to-use archive without requiring access to `/etc/letsencrypt`. AD CS
  managed private keys are encrypted locally; Certbot material is retained in
  owner-only toolkit storage. Downloads include leaf, chain, full-chain, key,
  and combined PEM formats. Generic DNS-01 renewals remain guided unless a DNS
  provider API is configured outside this workflow.
- **SNMP Tester** — manage reusable SNMPv2c/SNMPv3 credentials, hosts, and OID
  collections for GET and subtree-walk tests; build a live monitor set of up
  to 20 IF-MIB interfaces across saved hosts. Compact filled graphs place
  endpoint download (interface transmit) above a traffic-weighted zero line
  and endpoint upload (interface receive) below it. Hover a graph to inspect
  both rates at the nearest retained sample; polling intervals and a shared
  scrollable history window can be changed without discarding collected
  samples. Persistent monitor sets continue through navigation, minimize to
  the Live tools footer dock, and restore their bounded server-side history.
- **Wake-on-LAN** — send bounded magic packets to local broadcasts or custom
  routed broadcast/relay destinations, with reusable device groups and optional
  ping confirmation.
- **Webhook / API Tester** — send bounded HTTP requests and inspect status,
  timing, headers, and response content without following redirects.
- **Syslog Tools** — generate RFC 5424 messages or briefly collect bounded UDP
  or TCP Syslog traffic.

#### Traffic & Interfaces

- **Packet Capture** — retain bounded PCAP files from a local or
  SPAN/mirror-connected interface, with validated BPF filters, duration,
  packet-count, file-size, snapshot-length, and promiscuous-mode controls;
  inspect live or retained packet headers in a floating auto-scrolling viewer,
  download captures, or copy them to the Local Datastore for longer-term
  storage and direct inspection.
- **Wi-Fi / LAN Speed Test** — measure browser-to-toolkit latency, jitter,
  download, and upload performance on the local network.
- **iPerf3 Tester** — use an existing system `iperf3` binary to run bounded,
  authorization-confirmed TCP or UDP client tests, or start and stop a managed
  multi-test background server that is supervised, appears in Live tools and
  dashboard status, and resumes with the toolkit until explicitly stopped;
  completed server tests are retained as collapsed source-address cards with
  endpoint throughput, transfer, retransmits or loss/jitter, CPU, intervals,
  and bounded raw JSON.
- **DHCP Discover** — send a customizable Discover and inspect Offers without
  requesting or accepting a lease.
- **Packet Replay** — preview, rewrite, VLAN-tag/fan-out, and transmit raw
  Ethernet frames from hex or classic Ethernet PCAP files after explicit
  authorization confirmation; each replay is bounded by frame count and
  scheduled duration.

### Local Tools

#### Datastore

The contained Datastore manages files beneath `instance/datastore/` and
supports:

- list and grid views;
- multi-file drag-and-drop upload;
- file and folder selection, move, delete, and bulk ZIP download;
- folder drop targets, renaming, and collision-safe writes; and
- a safe, size-bounded plain-text viewer for any stored file; and
- access through custom toolkit profiles.

Paths cannot escape the Datastore root, symbolic links are ignored, partial
uploads are cleaned up, and configured storage/free-space limits are enforced
at write time. Datastore content is operational data and is not included in
profile backups.

#### File Transfers

System administrators can run contained local transfer services backed by a selected
Datastore folder or a runtime-only single file:

- **TFTP** with configurable bind address/port, trusted client networks,
  read/write policy, and incoming filename rewrites;
- **SFTP/SCP** with hashed password authentication, a persistent host key,
  trusted networks, atomic uploads, and no interactive shell; and
- **FTP** with passive-port controls, connection limits, trusted networks,
  atomic uploads, and explicit plaintext-security warnings.

All listeners are disabled by default. Runtime-only files are removed when the
corresponding service stops. Transfer history remains visible in the web UI.

### Automation

Automation is built from four reusable layers:

- **Automation → Automations** chooses run mode and connects definitions to
  state policy, staged action pipelines, and retained run history.
- **Automation → Schedules** is the reusable calendar timing library.
- **Automation → Conditions** is the reusable observation and trigger library.
- **Automation → Actions** is the reusable response library.

1. **Automations** choose manual, condition, or schedule run mode.
2. **Schedules** describe reusable calendar timing.
3. **Conditions** describe health observations and can be combined with ALL or
   ANY for condition-mode automations.
4. **Actions** describe trusted responses arranged into ordered stages.

Actions within a stage run in parallel; stages run sequentially. Continuation
policy can require full success, allow partial success, or proceed regardless
of result. Bounded, non-secret summaries from earlier stages can be passed to
later Webhook/API actions.

Available conditions include:

- multi-host ICMP reachability;
- DNS answer/availability checks across resolver matrices;
- multi-target Ping Quality thresholds for loss, latency, and jitter;
- DNS Performance thresholds for response time, failures, and answer
  consistency;
- per-host TCP service-state checks;
- SNMP rules with per-host AND logic and calculated scalar values; and
- multi-target TLS certificate health.

Available actions include:

- prompt-aware SSH command collection with Stored Commandlet loading,
  spreadsheet-style per-host variables, and fleet batching for up to 5,000
  targets;
- SFTP, SCP, or FTP file collection to the Datastore or retained artifacts;
- bounded packet capture to retained artifacts or the Datastore;
- RFC 5424 Syslog and metadata-only email notifications; and
- encrypted-header, templated Webhook/API notifications.

The scheduler runs independently of the browser. Durable SQLite claims and
renewable leases prevent duplicate work and allow abandoned jobs to be
recovered after a bounded expiry. Automations support one-second minimum check
intervals, trigger/recovery debounce, cooldowns, missed-schedule policy,
downloadable artifacts, retention controls, queue/concurrency limits, overlap
prevention, and automatic pruning.

See [Automation architecture and operations](docs/automations.md) for the state
model, pipeline contract, security boundaries, and extension points.

### Administration

The built-in system administrator can manage:

- users, password policy, idle timeout, and password changes;
- reusable custom access profiles with individual-tool permissions;
- server bind addresses, client allowlists, instance name, and preferred FQDN;
- installation-wide SMTP delivery for automation email notifications;
- selectable profile backup/restore with combine or replace behavior;
- mandatory encryption whenever an export contains credentials or secrets;
- automation retention, worker/queue limits, quotas, and free-disk reserve; and
- System Diagnostics, migrations, worker health, storage, dependencies, and an
  expandable, sanitized audit trail with resource context and curated
  before/after changes. Meaningful annotated actions are attributed to both
  operators and system administrators; routine polling and UI noise are omitted.

System Settings is separated into System, Email, Operations, and Accounts &
access views. Updates & Recovery is separated into Updates, Recovery points,
and Profile backups so advanced and destructive controls remain available
without crowding routine administration.

Operators receive the union of their assigned custom profiles. Unauthorized tools
are removed from navigation and remain blocked by the server if requested directly.

## Installation

### Requirements

- Python 3.10 or newer
- macOS, Linux, or Raspberry Pi OS
- network access from the toolkit host to the devices being tested

Install and start the toolkit:

```bash
git clone https://github.com/thewifininja/twn-toolkit.git
cd twn-toolkit
./install.sh
```

The installer checks dependencies, creates `.venv`, installs Python packages,
generates a self-signed certificate for a fresh installation, and starts the
web and automation services. Open one of the printed HTTPS URLs and create the
first administrator; there is no default login.

Running `./install.sh` again refreshes dependencies without replacing saved
instance data or changing an existing installation’s HTTP/HTTPS choice. If the
toolkit is already running, the installer restarts its managed processes so the
updated application code is active before installation completes.

After installation, normal upgrades no longer require Git, the GitHub CLI, or
manual tag selection. System administrators can use **Administration → Updates
& Recovery**, or run `./twn upgrade` when the web interface is unavailable. Both
paths verify the release bundle, stop services, create a complete matched code
and instance recovery point, install and validate the release, and automatically
restore the previous state after failure. See [Upgrade and
Recovery](docs/upgrade-recovery.md).

Installations running v0.10.2 or older require one final conventional upgrade
to v0.11.0, the first updater-enabled release. Future releases can then be
installed entirely through the built-in UI or CLI workflow.

For more detailed first-run and profile instructions, see
[QUICKSTART.md](QUICKSTART.md) or the searchable **Help** page inside the app.

## Running the service

```text
./twn start             Start web, scheduler, supervisor, and enabled services
./twn stop              Stop the toolkit
./twn restart           Restart the toolkit
./twn recover           Repair an orphaned/sudo-started server and start normally
./twn status            Show process state and usable access URLs
./twn logs              Show recent web and scheduler errors
./twn enable-https ...  Generate or regenerate toolkit-managed HTTPS
./twn disable-https     Return an existing installation to HTTP
./twn upgrade           Find and install the latest verified stable release
./twn backup            Create a matched code and instance recovery point
./twn rollback ID       Restore a matched recovery point
./twn fix-permissions   Repair runtime ownership after running with sudo
./twn adminreset        Remove users and return to first-launch setup
./twn reset-data        Remove saved profiles and API keys
```

The default web port is `5050`. Override it for one launch with:

```bash
TWN_TOOLKIT_PORT=8443 ./twn start
```

Fresh installations use HTTPS. Toolkit-managed certificates include localhost,
loopback addresses, the machine hostname, and any additional names supplied to
`./twn enable-https`. Administration settings can define a short instance name
and preferred FQDN without requiring that DNS already exist.

## Privileged operations

Most tools run without elevated privileges. A few operations may require OS
permission:

- **DHCP Discover** needs access to privileged UDP client port 68 and the
  selected interface.
- **Packet Replay** needs raw Ethernet/BPF access (`CAP_NET_RAW` or root on
  Linux; BPF permission may require `sudo` on macOS).
- Standard TFTP/FTP ports may require privileged bind permission; the default
  high ports avoid that requirement.

Starting the whole toolkit with `sudo` can make `instance/` root-owned. Return
to normal operation with `./twn recover`. The recovery command detects Linux or
macOS, verifies that a process occupying the configured port belongs to this
installation, stops orphaned toolkit processes, repairs instance and updater
metadata ownership, and starts the service as the invoking user. It will not
terminate an unrelated process that happens to use the same port. Use
`./twn fix-permissions` when only runtime ownership needs repair.

See [Packet Replay setup](docs/packet-replay.md) for platform-specific details.

## Security and data model

The toolkit is intentionally local-first:

- application passwords use scrypt hashes;
- session signing uses a private installation secret;
- automation action secrets are encrypted at rest;
- profile files and databases use owner-only permissions;
- login access is restricted to loopback and RFC 1918 clients by default; and
- secrets are never rendered back into forms or written to the audit trail.

Fortinet API tokens and several reusable credential stores remain sensitive
local instance data rather than entries in an external secrets vault. Protect
the host and the ignored `instance/` directory accordingly.

Profile backup/restore is selectable. Backups containing credentials require a
password-encrypted file; non-secret selections may be encrypted optionally.
Runtime activity, automation history/output, transfer history, and Datastore
files are not included.

SQLite stores activity, automation state, retained run metadata, and migration
ledgers. Numbered transactional migrations create local pre-change snapshots
when needed. No external SQL service is required.

TFTP and FTP do not encrypt traffic. Prefer SFTP/SCP whenever the target
supports it. Authentication and HTTPS do not make the toolkit appropriate for
unrestricted internet exposure.

## Project documentation

- [Quick Start](QUICKSTART.md) — installation, first login, saved profiles, and
  common operator workflows
- [Automation](docs/automations.md) — condition/action contracts, scheduling,
  state, retention, and pipeline behavior
- [Packet Replay](docs/packet-replay.md) — raw-packet permissions and platform
  setup
- [Upgrade and Recovery](docs/upgrade-recovery.md) — pre-upgrade backup,
  verification, and rollback procedure
- [Security Advisories](docs/security-advisories.md) — dependency-audit policy,
  active mitigations, and reviewed exceptions
- [Adding a Tool](docs/adding-a-tool.md) — internal module registration and
  shared UI/access conventions
- Built-in **Help** — searchable user guidance and release notes matching the
  installed application version

## Development

Install the pinned development dependencies and run the complete test suite:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Changes are developed on focused branches and merged into `main` through pull
requests after the Ubuntu and macOS CI jobs pass. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the branch, review, and release workflow.

For a local development server with automatic reload, first stop the background
service and then run:

```bash
source .venv/bin/activate
flask --app twn_toolkit run --debug --port 5050
```

New internal tools register metadata and endpoint ownership through the tool
registry so navigation, Favorites, custom access profiles, backup integration,
and authorization remain consistent. See
[docs/adding-a-tool.md](docs/adding-a-tool.md).

## Disclaimer

The WiFi Ninja’s Toolkit is provided as-is, without warranty of any kind. You
are responsible for reviewing actions, protecting credentials, and ensuring you
have authorization to use the toolkit in your environment. **Use at your own
risk.**

## License

Licensed under the [MIT License](LICENSE).
