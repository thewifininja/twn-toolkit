# The WiFi Ninja's Toolkit

A local-first browser toolkit for repeatable Fortinet administration and live
network troubleshooting. It is designed for an operator workstation or trusted
internal network—not as a permanent monitoring platform or internet-facing
service.

## Capabilities

### Fortinet Workflows

- Store and test local FortiGate and FortiAuthenticator connection profiles.
- Export managed APs, FortiSwitches, wireless clients, FortiSwitch clients,
  FortiAuthenticator MAC devices, and MAC group memberships.
- Rename managed APs and FortiSwitches interactively or from CSV, with dry runs
  and read-back verification.
- Reorder managed FortiSwitches by drag-and-drop or alphabetize their displayed
  names, with a move preview and post-change verification.
- Preview and remove FortiAuthenticator group memberships or delete MAC devices
  globally with overlap warnings and typed confirmation.

### Network Tools

- **What’s My IP?:** show the address used to reach the toolkit and, through a
  browser-side ipify lookup, the client's public internet address.
- **Subnet Excluder:** subtract IPv4 or IPv6 CIDR networks from parent ranges.
- **Multi-Host Ping:** troubleshoot reachability, latency, and loss with
  reusable host profiles, live Canvas charts, lockable history views, and CSV
  export. History exists only in the current browser session.
- **Multi-SSH:** run one command sequence across multiple SSH hosts.
- **DNS Lookup Tester:** compare DNS answers and lookup latency across resolvers.
- **RADIUS Authentication Test:** compare PAP or CHAP authentication and decode
  returned attributes.
- **Wi-Fi / LAN Speed Test:** measure browser-to-toolkit latency, jitter,
  download, and upload throughput on the local network.
- **Certificate Chain Inspector:** inspect the exact TLS chain supplied by a
  server and validate hostname, dates, chain order, and local trust.
- **SNMP Tester:** validate SNMPv2c or SNMPv3 access using reusable credentials,
  devices, and numeric OID collections.
- **TCP Port Scanner:** check selected ports across authorized hosts.
- **NTP Tester:** compare clock offset, delay, jitter, stratum, reference
  identity, and synchronization health across reusable server lists.
- **Traceroute:** stream UDP or ICMP traces for up to 10 destinations from
  reusable lists into live graphical paths and traditional text output.

## Quick Start

```bash
./install.sh
```

The installer checks Python, creates `.venv`, installs requirements, starts the
service, and can safely be run again. Open http://127.0.0.1:5050 and create the
first administrator account.

For a manual installation:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
./twn start
```

The home page separates Fortinet workflows from vendor-neutral network tools.

## Local Service

```text
./twn start     Start in the background
./twn stop      Stop the service
./twn restart   Restart the service
./twn status    Show status and URL
./twn logs      Show recent server errors
./twn adminreset  Remove users and return to first-launch setup
```

The launcher supports macOS, Linux, and Raspberry Pi OS. Port 5050 is used by
default because macOS Control Center commonly occupies port 5000. Override it
when needed:

```bash
TWN_TOOLKIT_PORT=8000 ./twn start
```

By default, the service listens on all IPv4 interfaces but accepts clients only
from loopback and the RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`,
and `192.168.0.0/16`). It runs in the background and writes its PID and logs
under the ignored `instance/` directory.

For first-time setup, API permissions, normal usage, and preparing a clean copy
for another user, see [QUICKSTART.md](QUICKSTART.md).

## CSV Format

Bulk rename tasks expect:

```csv
identifier,current_name,new_name,vdom
S124ENTF00000001,Old Switch,Closet_1,root
```

Required columns:

- `new_name`
- Either `identifier` or `current_name`

Optional columns:

- `current_name`: Friendly current name used in results when `identifier` is present.
- `vdom`: Overrides the selected profile's default VDOM.

Rename task pages also provide **Load Current Devices**. This polls the FortiGate,
shows current names in a scrollable editor, and lets you select and rename devices
without preparing a CSV. Dry run is enabled by default. AP updates use `wtp-id`
and FortiSwitch updates use `switch-id` as stable identifiers when available.
For managed FortiSwitches, The WiFi Ninja's Toolkit detects whether the appliance exposes the
legacy writable `name` field or the FortiOS 7.4+ renameable `switch-id` key and
uses the matching update and read-back verification flow.

## Security and Local Data

On first launch, the toolkit requires creation of an administrator account;
there is no default username or password. Passwords are stored as scrypt hashes
in owner-readable `instance/auth.json`. Signed login sessions use an independently
generated owner-readable secret in `instance/session_secret`. Administrators can
manage users, change passwords, and configure the idle timeout, minimum password
length, and optional character-complexity requirements from **Settings**.

If every administrator is locked out, stop the service and run:

```bash
./twn adminreset
./twn start
```

Equivalently, delete `instance/auth.json` while the service is stopped. The next
browser visit returns to administrator setup. This does not delete device
profiles, SNMP credentials, API keys, or the session secret.

Authentication and the default private-network allowlist protect access to the
application, but they do not make it suitable for direct internet exposure. Put
TLS in front of the toolkit before allowing logins across an untrusted network.

Administrators can open **Settings → Server access** to listen on all network
interfaces and allow specific IPv4/IPv6 addresses or CIDR networks. Loopback is
always allowed. Saving starts a browser-managed service restart. If the new
listener fails, the launcher restores and starts the previous server settings.
The current remote administrator cannot save an allowlist that excludes their
own client address.

`TWN_TOOLKIT_HOST` still overrides the saved listen setting when explicitly set
in the service environment. Trusted-client filtering remains active.

FortiGate API keys are stored in `instance/profiles.json`. FortiAuthenticator
usernames and Web Service API keys are stored in
`instance/fortiauthenticator_profiles.json`. Ping profiles are stored in
`instance/ping_profiles.json`; DNS host and server profiles use separate
`instance/dns_hosts_profiles.json` and `instance/dns_servers_profiles.json` files.
RADIUS server and credential profiles are stored separately in
`instance/radius_servers_profiles.json` and `instance/radius_credentials_profiles.json`;
request attributes use `instance/radius_attributes_profiles.json`.
SNMP credentials, hosts, and OID collections use separate
`instance/snmp_*_profiles.json` files.
TCP scanner host and port sets use `instance/port_scan_*_profiles.json`.
NTP and Traceroute host lists use `instance/ntp_host_profiles.json` and
`instance/traceroute_host_profiles.json`.
These files have owner-only permissions and are
excluded from Git, but their contents are not encrypted. Treat the host as trusted.

Multi-Host Ping measurements and chart history are held in the browser session.
Reloading or closing the page discards that history unless it was exported.

## FortiGate API Notes

Default endpoint templates:

- APs: `/api/v2/cmdb/wireless-controller/wtp/{current_name}`
- FortiSwitches: `/api/v2/cmdb/switch-controller/managed-switch/{current_name}`
- Export AP Data: `/api/v2/cmdb/wireless-controller/wtp`
- Export FortiSwitch Data: `/api/v2/cmdb/switch-controller/managed-switch`
- Export Wireless Clients: `/api/v2/monitor/wifi/client`
- Export FortiSwitch Clients: `/api/v2/monitor/switch-controller/detected-device`

The endpoint template is editable before each run because FortiOS object paths can vary by version and feature set.
Some export tasks also have alternate endpoints; if a path returns 404, The WiFi Ninja's Toolkit tries the next candidate and updates the form with the endpoint that worked.

Export field lists support fallbacks:

```text
Serial Number=serial-number|serial|serial_number|sn, Model=model|platform
```

The text before `=` becomes the CSV header. The values after `=` are tried from left to right until data is found.

On export task pages, use **Load Available Fields** to poll the selected endpoint,
choose columns with checkboxes, drag rows into CSV order, and then select
**Apply Selected Fields**. Use **Fetch Data** to preview the resulting table.

To remove saved profiles and API keys before sharing a copy, run:

```bash
flask --app twn_toolkit reset-data
```

## Development Server

For local development with automatic code reloading:

```bash
source .venv/bin/activate
flask --app twn_toolkit run --debug --port 5050
```

Stop the background service first with `./twn stop` if it is already running.
