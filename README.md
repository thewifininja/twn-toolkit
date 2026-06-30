# The WiFi Ninja's Toolkit

A small Flask app for repeatable Fortinet administration and standalone network
operations tasks.

## What it does

- Stores local FortiGate connection profiles.
- Tests profile connectivity with the FortiGate monitor API.
- Bulk renames managed APs in the browser or from CSV.
- Bulk renames managed FortiSwitches in the browser or from CSV.
- Exports managed AP data to CSV.
- Exports managed FortiSwitch data to CSV.
- Exports wireless clients to CSV.
- Exports FortiSwitch clients to CSV.
- Stores local FortiAuthenticator profiles using Web Service API keys.
- Previews and exports FortiAuthenticator MAC devices and group memberships.
- Removes selected group memberships or deletes selected MAC devices globally
  with previews, overlap warnings, and typed confirmation.
- Subtracts CIDR exclusions from IPv4 or IPv6 parent networks.
- Monitors multiple hosts with a live browser-based ping view.
- Saves reusable ping host collections with optional friendly names.
- Runs command sequences against multiple SSH hosts with per-host output.
- Compares DNS answers and response times across reusable host and resolver profiles.
- Tests PAP or CHAP credentials against multiple saved RADIUS servers, with
  reusable request-attribute profiles and decoded standard reply attributes.
- Provides a task registry so more CSV/API tasks can be added cleanly later.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./twn start
```

Open http://127.0.0.1:5050.

The home page separates Fortinet workflows from standalone generic network tools.

## Local Service

```text
./twn start     Start in the background
./twn stop      Stop the service
./twn restart   Restart the service
./twn status    Show status and URL
./twn logs      Show recent server errors
```

The launcher supports macOS, Linux, and Raspberry Pi OS. Port 5050 is used by
default because macOS Control Center commonly occupies port 5000. Override it
when needed:

```bash
TWN_TOOLKIT_PORT=8000 ./twn start
```

The service binds to localhost only, runs in the background, and writes its PID
and logs under the ignored `instance/` directory.

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

## Notes

FortiGate API keys are stored in `instance/profiles.json`. FortiAuthenticator
usernames and Web Service API keys are stored in
`instance/fortiauthenticator_profiles.json`. Ping profiles are stored in
`instance/ping_profiles.json`; DNS host and server profiles use separate
`instance/dns_hosts_profiles.json` and `instance/dns_servers_profiles.json` files.
RADIUS server and credential profiles are stored separately in
`instance/radius_servers_profiles.json` and `instance/radius_credentials_profiles.json`;
request attributes use `instance/radius_attributes_profiles.json`.
These files have owner-only permissions and are
excluded from Git, but their contents are not encrypted. Treat the host as trusted.

Default endpoint templates:

- APs: `/api/v2/cmdb/wireless-controller/wtp/{current_name}`
- Switches: `/api/v2/cmdb/switch-controller/managed-switch/{current_name}`
- Export AP Data: `/api/v2/cmdb/wireless-controller/wtp`
- Export Switch Data: `/api/v2/cmdb/switch-controller/managed-switch`
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
