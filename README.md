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

Current release: **v0.9.0**

> [!CAUTION]
> This software can send packets, test credentials, change managed devices,
> expose local file-transfer listeners, and run commands on remote systems. Use
> it only on infrastructure you are authorized to operate. It is not designed
> for direct exposure to the public internet.

## Navigation at a glance

- **Dashboard** — metrics, activity, scoreboard, Favorites, and widget layout
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

The landing page is an operational dashboard rather than a directory of links.
It provides:

- time-filtered counters for pings, DNS, SNMP, API calls, traceroutes, speed
  tests, Syslog, and other toolkit activity;
- recent activity and a per-user scoreboard;
- administrator-managed widget visibility and drag-and-drop ordering; and
- personal Favorites managed from the persistent sidebar.

Dashboard layout can be included in profile backups. Activity history and
counters are intentionally excluded.

### Fortinet Tools

#### FortiGate, FortiAP, and FortiSwitch

- Save and test multiple FortiGate profiles with API tokens, VDOM defaults,
  TLS policy, and bounded timeouts.
- Export managed AP, FortiSwitch, wireless-client, and switch-client inventory.
- Rename managed APs and FortiSwitches interactively or from CSV, with dry-run
  previews and read-back verification.
- Reorder managed FortiSwitches by drag-and-drop or alphabetically.
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
- **DNS Lookup Tester** — compare record values and response times across
  multiple resolvers.
- **NTP Tester** — inspect offset, delay, jitter, stratum, reference identity,
  and synchronization health.
- **Path MTU Tester** — find the largest unfragmented IPv4 or IPv6 ICMP packet
  that reaches a target.
- **Traceroute** — run UDP or ICMP traces for multiple destinations with live
  graphical hops and text output.

#### Multi-Host Tools

- **Multi-Host Ping** — graph reachability, latency, and loss for a validated
  target snapshot; update targets without discarding unchanged history.
- **Multi-SSH** — run prompt-aware command sequences concurrently, with friendly
  host names, per-command timeouts, and downloadable results.
- **Multi-Transfer** — fetch files concurrently over SFTP, SCP, or FTP into the
  Datastore or a one-shot ZIP, using collision-safe filename templates.
- **TCP Port Scanner** — check individual ports or ranges across authorized
  hosts.

#### Services & Protocols

- **RADIUS Authentication Test** — compare PAP and CHAP results and returned
  attributes; optional `eapol_test` support adds PEAP/MSCHAPv2 and EAP-TLS.
- **Certificate Chain Inspector** — inspect the exact TLS chain presented by a
  server and validate dates, hostname, order, intermediates, and local trust.
- **SNMP Tester** — manage reusable SNMPv2c/SNMPv3 credentials, hosts, and OID
  collections for GET and subtree-walk tests.
- **Webhook / API Tester** — send bounded HTTP requests and inspect status,
  timing, headers, and response content without following redirects.
- **Syslog Tools** — generate RFC 5424 messages or briefly collect bounded UDP
  or TCP Syslog traffic.

#### Traffic & Interfaces

- **Wi-Fi / LAN Speed Test** — measure browser-to-toolkit latency, jitter,
  download, and upload performance on the local network.
- **DHCP Discover** — send a customizable Discover and inspect Offers without
  requesting or accepting a lease.
- **Packet Replay** — preview, rewrite, VLAN-tag/fan-out, and transmit raw
  Ethernet frames from hex or classic Ethernet PCAP files.

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

Administrators can run contained local transfer services backed by a selected
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

Automation is built from three reusable layers:

- **Automation → Conditions** is the reusable observation and trigger library.
- **Automation → Actions** is the reusable response library.
- **Automation → Automations** connects those definitions to schedules, state
  policy, staged pipelines, and retained run history.

1. **Conditions** describe observations or schedules.
2. **Actions** describe trusted responses.
3. **Automations** connect one condition to one or more ordered action stages.

Actions within a stage run in parallel; stages run sequentially. Continuation
policy can require full success, allow partial success, or proceed regardless
of result. Bounded, non-secret summaries from earlier stages can be passed to
later Webhook/API actions.

Available conditions include:

- manual triggers and timezone-aware calendar schedules;
- multi-host ICMP reachability;
- DNS answer/availability checks across resolver matrices;
- per-host TCP service-state checks;
- SNMP rules with per-host AND logic and calculated scalar values; and
- multi-target TLS certificate health.

Available actions include:

- prompt-aware multi-host SSH command collection;
- SFTP, SCP, or FTP file collection to the Datastore or retained artifacts;
- RFC 5424 Syslog notifications; and
- encrypted-header, templated Webhook/API notifications.

The scheduler runs independently of the browser. Automations support one-second
minimum check intervals, trigger/recovery debounce, cooldowns, missed-schedule
policy, downloadable artifacts, retention controls, queue/concurrency limits,
overlap prevention, and automatic pruning.

See [Automation architecture and operations](docs/automations.md) for the state
model, pipeline contract, security boundaries, and extension points.

### Administration

The built-in administrator can manage:

- users, password policy, idle timeout, and password changes;
- reusable custom access profiles with individual-tool permissions;
- server bind addresses, client allowlists, instance name, and preferred FQDN;
- selectable profile backup/restore with combine or replace behavior;
- mandatory encryption whenever an export contains credentials or secrets;
- automation retention, worker/queue limits, quotas, and free-disk reserve; and
- System Diagnostics, migrations, worker health, storage, dependencies, and a
  sanitized administrative audit trail.

Unauthorized tools are removed from navigation and remain blocked by the
server if requested directly.

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
instance data or changing an existing installation’s HTTP/HTTPS choice.

For more detailed first-run and profile instructions, see
[QUICKSTART.md](QUICKSTART.md) or the searchable **Help** page inside the app.

## Running the service

```text
./twn start             Start web, scheduler, supervisor, and enabled services
./twn stop              Stop the toolkit
./twn restart           Restart the toolkit
./twn status            Show process state and usable access URLs
./twn logs              Show recent web and scheduler errors
./twn enable-https ...  Generate or regenerate toolkit-managed HTTPS
./twn disable-https     Return an existing installation to HTTP
./twn fix-permissions   Repair instance ownership after running with sudo
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
to normal operation with `./twn fix-permissions`.

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
- [Adding a Tool](docs/adding-a-tool.md) — internal module registration and
  shared UI/access conventions
- Built-in **Help** — searchable user guidance and release notes matching the
  installed application version

## Development

Run the complete test suite:

```bash
.venv/bin/python -m unittest discover -s tests
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
