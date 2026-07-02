# The WiFi Ninja's Toolkit Quick Start

## Requirements

- Python 3.10 or newer
- macOS, Linux, or Raspberry Pi OS
- Network access to the appliances you want to manage
- For FortiGate workflows: a REST API administrator and token
- For FortiAuthenticator workflows: an administrator with Web service access
  and its emailed API access key

A read-only API profile is sufficient for exports. Rename tasks require
read-write permission for the wireless-controller or switch-controller resource.
FortiAuthenticator cleanup requires permission to change Users and Devices
resources.

## Install

From the project folder:

```bash
./install.sh
```

The installer creates the virtual environment, installs requirements, and starts
the toolkit. It is safe to run again when dependencies need refreshing.

For manual setup:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
./twn start
```

Open <http://127.0.0.1:5050>.

The service runs in the background. Manage it with:

```bash
./twn status
./twn logs
./twn restart
./twn stop
```

## Add a FortiGate

1. Enter a profile name.
2. Enter the complete FortiGate URL, including a custom port when needed:
   `https://192.0.2.10:8443`
3. Paste the REST API token.
4. Enter the default VDOM, usually `root`.
5. Leave TLS verification enabled when the FortiGate has a trusted certificate.
6. Optionally select **Use as default profile**.
7. Save the profile and use **Test** to verify connectivity.

Profiles and API tokens are stored only on the local machine in
`instance/profiles.json`. Treat that machine and file as sensitive.

## Add a FortiAuthenticator

1. On FortiAuthenticator, use an administrator account with **Web service
   access** enabled and note the emailed Web Service API Access Key.
2. Enter a profile name and the appliance root URL, such as
   `https://192.0.2.20`.
3. Enter the administrator username and Web Service API Access Key. Do not use
   the account's interactive login password.
4. Leave TLS verification enabled when the appliance has a trusted certificate.
5. Optionally adjust the timeout and select **Use as default profile**.
6. Save the profile and use **Test** to verify access.

FortiAuthenticator credentials are stored locally in
`instance/fortiauthenticator_profiles.json`.

## Run Tasks

### Exports

1. Open an export task and select a profile.
2. Use the default CSV fields, or expand **Select columns from FortiGate**.
3. Select **Load Available Fields**, choose and reorder columns, then select
   **Apply Selected Fields**.
4. Use **Fetch Data** to preview results or **Export CSV** to download them.

### Renames

Use either workflow:

- Select **Load Current Devices** to edit selected names in the browser.
- Upload a CSV using the inline example or **Download CSV Template**.

Dry run is enabled by default. Review the results and select
**Apply These Changes** to perform the live updates. The WiFi Ninja's Toolkit reads each object
back after an update and reports whether the requested name was verified.

## FortiAuthenticator Tasks

### MAC Devices

Use **Fetch Data** for an in-page preview or **Export CSV** for the complete
paginated inventory.

### MAC Group Memberships

Preview or export all device-to-group associations, including explicit device,
group, and membership IDs.

### MAC Device Cleanup

1. Load groups and select the group to clean.
2. Choose either **Remove devices from this group only** or **Delete MAC devices
   globally**.
3. Build and review the preview. Global deletion highlights devices that also
   belong to other groups.
4. All targets are selected by default; deselect anything that should remain.
5. Type the exact confirmation phrase calculated for the selected count.

The app re-fetches and validates selected IDs immediately before execution.
Global deletion removes the MAC device object, not just its membership.

## Network Tools

The **Network Tools** workspace contains vendor-neutral diagnostics. Some tools
have their own reusable profiles, but none require a FortiGate profile.

- **Subnet Excluder** subtracts comma-, space-, or line-separated CIDRs from
  parent networks. Enter `rfc1918` to use all private IPv4 ranges.
- **Multi-Host Ping** troubleshoots reachability, latency, and loss from the
  toolkit host. Save reusable host profiles with optional `Name = host` labels.
  Charts provide 1-, 2-, and 5-minute views, precise historical navigation,
  hover details, and CSV export. History belongs to the current browser session;
  reloading or closing the page discards it. Select **Stop** to end polling.
- **Multi-SSH** sends the same command sequence to multiple devices using an
  interactive SSH shell. Passwords are used only for the current request and
  are not saved. Unknown host keys are rejected unless explicitly allowed.
- **DNS Lookup Tester** runs each hostname lookup through each resolver, showing
  returned records and response time. Host lists and resolver lists are saved
  independently, so either can be reused in different test combinations.
- **RADIUS Authentication Test** compares PAP or CHAP authentication across
  saved servers and reports response time, result codes, and returned
  attributes. Server, credential, and request-attribute profiles are reusable.
  Shared secrets and test credentials are stored locally without encryption.
- **Wi-Fi / LAN Speed Test** measures latency, jitter, download, and upload
  throughput between the browser and the toolkit server. Open it from another
  device for a meaningful result; it does not measure internet service speed.
- **Certificate Chain Inspector** retrieves the exact certificates supplied by
  an HTTPS server and reports hostname matching, validity dates, chain order,
  TLS details, and validation against the toolkit host's trust store. Trusted
  roots are not silently added to the displayed server-supplied chain.
- **SNMP Tester** stores separate SNMPv2c/SNMPv3 credential profiles, host
  mappings, and reusable numeric OID collections. Collections support scalar
  GET operations and bounded subtree walks using a `walk:` label prefix.
- **TCP Port Scanner** checks selected TCP ports across reusable authorized-host
  and port profiles, with connection timing and service-name hints. Selecting a
  profile immediately updates the scan inputs. It is limited to 50 hosts, 200
  unique ports, and 5,000 host/port combinations per scan.
- **NTP Tester** tests up to 20 servers concurrently from reusable server
  profiles. It reports average clock offset, round-trip delay, jitter, stratum,
  reference identity, leap status, root delay, and root dispersion.
- **Traceroute** follows IPv4 or IPv6 destinations using UDP or ICMP probes,
  streaming each result into a latency-colored hop path and live text output.
  Up to 10 destinations can be queued per run, two traces execute concurrently,
  reusable destination profiles are supported, and long-running traces can be
  cancelled from the page.

Multi-SSH commands execute on real devices. Review the host list and commands
carefully before selecting the required execution confirmation.

## Reset Before Sharing

The WiFi Ninja's Toolkit persists Fortinet connection profiles and reusable
ping, DNS, RADIUS, SNMP, and TCP scanner profiles. To remove them:

```bash
flask --app twn_toolkit reset-data
```

Confirm the prompt. For scripts or packaging:

```bash
flask --app twn_toolkit reset-data --yes
```

This removes FortiGate, FortiAuthenticator, ping, DNS, RADIUS, SNMP, TCP
port-scanner, NTP, and Traceroute profile files from `instance/`. It does not
modify application code.
The `instance/` and `.venv/` directories are excluded by `.gitignore`.

After resetting, share the project without `.venv/`, `.git/`, or `instance/`.
The recipient can follow this guide to create their own environment and profile.

## Local Network Access

An administrator can open **Settings → Server access**, select **All network
interfaces**, and enter each trusted client address or CIDR network. **Save and
Restart** applies the listener change without requiring terminal access. The
toolkit always permits local loopback access and prevents a remote administrator
from saving an allowlist that excludes their current address.

Authentication and an IP allowlist do not make the service suitable
for direct internet exposure. Keep access to trusted internal networks and use a
TLS reverse proxy for any deployment that crosses an untrusted network.
