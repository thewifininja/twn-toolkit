# The WiFi Ninja's Toolkit

A local-first browser toolkit for repeatable Fortinet administration and live
network troubleshooting. It is designed for an operator workstation or trusted
internal network—not as a permanent monitoring platform or internet-facing
service.

## Capabilities

### Dashboard

- Track time-filtered toolkit metrics, user rankings, and recent activity.
- Administrators can globally show, hide, and reorder metric widgets; hidden
  widgets remain available in edit mode and new metrics appear automatically.
- Dashboard layout can be selected independently during profile backup/restore;
  activity history and counters are intentionally excluded.

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
- **Multi-SSH:** run one command sequence across multiple SSH hosts with
  prompt-aware completion, a configurable default timeout, and per-command
  overrides such as `[timeout=600] diag debug report`. Targets optionally use
  `Friendly Name = hostname-or-IP` for clearer results and export filenames.
- **DNS Lookup Tester:** compare DNS answers and lookup latency across resolvers.
- **RADIUS Authentication Test:** compare PAP or CHAP authentication and decode
  returned attributes. Optional `eapol_test` integration adds PEAP/MSCHAPv2 and
  EAP-TLS with request-scoped certificate uploads.
- **Wi-Fi / LAN Speed Test:** measure browser-to-toolkit latency, jitter,
  download, and upload throughput on the local network.
- **Certificate Chain Inspector:** inspect the exact TLS chain supplied by a
  server and validate hostname, dates, chain order, and local trust.
- **SNMP Tester:** validate SNMPv2c or SNMPv3 access using reusable credentials,
  devices, and numeric OID collections.
- **TCP Port Scanner:** check selected ports across authorized hosts.
- **NTP Tester:** compare clock offset, delay, jitter, stratum, reference
  identity, and synchronization health across reusable server lists.
- **DHCP Discover:** send a Discover with a custom parameter request list and
  inspect matching Offers without sending a Request or accepting a lease.
- **Packet Replay:** preview, modify, and transmit raw Ethernet
  frames from hex or classic PCAP on an authorized wired test network.
- **Path MTU Tester:** binary-search the largest unfragmented IPv4 or IPv6 ICMP
  packet that reaches a destination.
- **Webhook / API Tester:** send a bounded HTTP request without following
  redirects and inspect timing, status, headers, and response content.
- **Syslog Tools:** generate RFC 5424 test messages or collect a bounded number
  of UDP or TCP syslog messages during a short listening window.
- **Traceroute:** stream UDP or ICMP traces for up to 10 destinations from
  reusable lists into live graphical paths and traditional text output.
- **Multi-Host Ping:** snapshots validated targets when a run starts; an
  explicit Update targets control applies later edits without clearing retained
  history for unchanged hosts.

### Automations

- Define reusable multi-host ping conditions and reusable SSH collection
  actions, then reference them from multiple automations.
- Monitor DNS names through multiple resolvers and trigger on query failures or
  unexpected A, AAAA, CNAME, MX, NS, PTR, or TXT answers.
- Monitor TCP services with a custom list of individual ports or ranges per
  host, with expected-open and expected-closed state checks.
- Build SNMP conditions from shared hosts and per-host AND rules. OID profiles
  can expose reusable derived values such as
  `calc: Memory Usage % = percent(Current Memory KB, Total Memory KB)`.
- Schedule checks as frequently as once per second with consecutive failure,
  recovery, and cooldown thresholds.
- Use a reusable Manual trigger condition for on-demand automations that run
  only when an administrator selects **Run now**.
- Build reusable calendar conditions containing multiple one-time, daily,
  weekly, alternating-week, monthly-date, and ordinal-weekday rules. Each
  schedule has an explicit timezone and configurable missed-run policy.
- Trigger concurrent SSH command collection against management targets and
  retain per-host output with the incident run.
- Send templated RFC 5424 syslog notifications to multiple UDP or TCP
  collectors and retain per-destination delivery results.
- Send encrypted-header Webhook/API notifications with JSON-safe trigger
  variables, accepted-status policy, and retained per-endpoint results.
- Build ordered action pipelines with user-defined stages. Actions inside a
  stage run in parallel, while additional stages wait and run sequentially.
- Choose whether a later stage always runs, requires success-or-partial results,
  or requires every action in the preceding stage to succeed.
- Pass bounded, non-secret earlier-stage summaries into later Webhook/API
  actions without automatically exposing raw SSH captures or credentials.
- Download a run as a ZIP containing metadata and per-host text output.
- Delete individual collected runs or clear all collected action data for an
  automation while preserving condition-check history.
- Run checks in a dedicated scheduler process even when no browser is open.
- Extend trusted internal condition and action registries without rewriting the
  scheduler. See [Automations](docs/automations.md).

## Quick Start

```bash
./install.sh
```

The installer checks Python, creates `.venv`, installs requirements, generates
a self-signed certificate for a fresh installation, and starts the service. It
can safely be run again without changing an existing installation's HTTP/HTTPS
choice. Open the printed HTTPS URL, review the browser's certificate warning,
and create the first administrator account.

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
./twn status    Show web and automation scheduler status
./twn logs      Show recent web and automation scheduler errors
./twn enable-https [hostname-or-IP ...]  Generate and enable local HTTPS
./twn disable-https  Return to HTTP while retaining TLS files
./twn fix-permissions  Repair instance ownership after sudo mode
./twn adminreset  Remove users and return to first-launch setup
./twn reset-data   Remove saved profiles and API keys
```

If the toolkit was previously started with `sudo`, startup checks for
root-owned files under `instance/` and offers `./twn fix-permissions` before
trying to launch a service that cannot write its own runtime files.

The launcher supports macOS, Linux, and Raspberry Pi OS. Port 5050 is used by
default because macOS Control Center commonly occupies port 5000. Override it
when needed:

```bash
TWN_TOOLKIT_PORT=8000 ./twn start
```

### HTTPS

Fresh installations use a generated self-signed HTTPS certificate by default.
Existing installations retain their current protocol during upgrades. To
enable HTTPS manually or add it to an older HTTP installation:

```bash
./twn enable-https toolkit.local 192.0.2.25
```

The certificate automatically includes localhost, loopback addresses, and the
machine hostname. Supply every additional stable hostname or IP address used to
open the toolkit. `./twn status` prints the active `https://` URL. Browsers warn
until the self-signed certificate is explicitly trusted; encryption still
works despite that warning.

The helper safely restarts a running toolkit. The private key is stored as
`instance/tls/key.pem` with owner-only permissions and is excluded with the
rest of `instance/` from source control and profile backups. Run
`./twn disable-https` to restart over HTTP; the certificate files are retained.
Advanced deployments can set both
`TWN_TOOLKIT_CERTFILE` and `TWN_TOOLKIT_KEYFILE` to an externally managed PEM
certificate and matching owner-only private key.

Administration → Settings provides a short instance name and optional preferred
FQDN. These values are validated syntactically without performing a DNS lookup.
The short name identifies browser tabs and the sidebar; the FQDN becomes the
preferred launcher/status URL. When using the toolkit-managed self-signed
certificate, explicitly select certificate regeneration while saving to add the
new identity to its SANs. Regeneration changes the certificate fingerprint.

The DHCP Discover tool binds privileged UDP client port 68 and pins traffic to
the selected interface. Start the toolkit with suitable OS privileges when
using that tool (for example, as root on a dedicated diagnostic host, or with
Linux `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW` capabilities). The web page
reports a permission error when those privileges are unavailable.

The Packet Replay tool sends raw Ethernet frames from the toolkit host. Use it
only on networks where you are authorized to transmit test traffic. Wired
Ethernet is the intended target; wireless frame injection is not supported. On
Linux, the toolkit uses a native raw Ethernet socket and needs root or
`CAP_NET_RAW`. On macOS/BSD-like systems, it falls back to Scapy/libpcap and may
need to run with `sudo` so it can open BPF packet devices. Administrators can
grant Packet Replay to non-admin users through access profiles. A successful
send reports the selected interface and the sender backend used. See
[Packet Replay setup](docs/packet-replay.md) for platform-specific steps.

PEAP/MSCHAPv2 and EAP-TLS testing requires the `eapol_test` executable from the
wpa_supplicant project. On Debian and Raspberry Pi OS it is provided by the
`eapoltest` package. PAP and CHAP testing do not require it. CA certificates,
client certificates, and private keys uploaded for an EAP test are placed in a
private temporary directory and removed when the test finishes.

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

Automation definitions, runtime state, condition history, and retained action
output are stored in `instance/automations.sqlite3`. Saved automation action
configuration is encrypted at rest using the installation's private session
secret. Automation definitions containing credentials can only be exported in
an encrypted profile backup; runtime history and captured output are excluded
from backups.

Multi-Host Ping measurements and chart history are held in the browser session.
Reloading or closing the page discards that history unless it was exported.

## Disclaimer

The WiFi Ninja's Toolkit is provided as-is, without warranty of any kind. It is
intended for use by network administrators and operators who understand the
impact of the actions they perform.

Some tools may make configuration changes, send authentication requests, query
logs, run diagnostics, or interact with infrastructure using stored credentials
or API tokens. You are responsible for reviewing actions before running them,
protecting stored credentials, and ensuring you have authorization to use the
toolkit in your environment.

Use at your own risk.

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
./twn stop
./twn reset-data
```

## Development Server

For local development with automatic code reloading:

```bash
source .venv/bin/activate
flask --app twn_toolkit run --debug --port 5050
```

Stop the background service first with `./twn stop` if it is already running.

## Internal Tool Development

New internal tools should register their metadata and route ownership through the
tool registry so navigation, favorites, access profiles, and authorization stay
consistent. See [docs/adding-a-tool.md](docs/adding-a-tool.md).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
