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
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Start

```bash
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

## Generic Tools

The **Generic Tools** workspace does not use Fortinet profiles.

- **Subnet Excluder** subtracts comma-, space-, or line-separated CIDRs from
  parent networks. Enter `rfc1918` to use all private IPv4 ranges.
- **Multi-Host Ping** runs repeated ICMP checks from the machine hosting
  The WiFi Ninja's Toolkit. Host collections can be saved as profiles, and
  optional friendly names use `Name = host`. Select **Stop** to end polling.
- **Multi-SSH** sends the same command sequence to multiple devices using an
  interactive SSH shell. Passwords are used only for the current request and
  are not saved. Unknown host keys are rejected unless explicitly allowed.
- **DNS Response Time** runs each host lookup against each DNS server, showing
  returned records and response time. Host lists and DNS server lists are saved
  independently, so either can be reused in different test combinations.
- **RADIUS Authentication Test** sends PAP or CHAP Access-Requests to one or
  more saved RADIUS servers and reports Access-Accept, Access-Reject,
  Access-Challenge, response time, and returned attributes. Shared secrets and
  test credentials are stored locally and are not encrypted. Additional
  Access-Request attributes can be saved as reusable profiles using
  `Name = value`; unknown standard and vendor attributes can be sent in raw
  hexadecimal form. Known standard response attributes are decoded by name and
  type, while unknown attributes retain their numeric identity and raw hex.
- **Wi-Fi / LAN Speed Test** measures latency, jitter, download, and upload
  throughput between the browser and the toolkit server. Open it from another
  device for a meaningful result; it does not measure internet service speed.
- **Certificate Chain Inspector** retrieves the exact certificates supplied by
  an HTTPS server and reports hostname matching, validity dates, chain order,
  TLS details, and validation against the toolkit host's trust store. Trusted
  roots are not silently added to the displayed server-supplied chain.

Multi-SSH commands execute on real devices. Review the host list and commands
carefully before selecting the required execution confirmation.

## Reset Before Sharing

The WiFi Ninja's Toolkit persists FortiGate profiles, FortiAuthenticator
profiles, API keys, and saved ping profiles. To remove them:

```bash
flask --app twn_toolkit reset-data
```

Confirm the prompt. For scripts or packaging:

```bash
flask --app twn_toolkit reset-data --yes
```

This removes `instance/profiles.json`,
`instance/fortiauthenticator_profiles.json`, and
`instance/ping_profiles.json`, `instance/dns_hosts_profiles.json`, and
`instance/dns_servers_profiles.json`, plus the RADIUS profile files; it does not
modify the application code.
The `instance/` and `.venv/` directories are excluded by `.gitignore`.

After resetting, share the project without `.venv/`, `.git/`, or `instance/`.
The recipient can follow this guide to create their own environment and profile.

## Local Network Access

To intentionally allow another machine on the same trusted network to connect,
stop the service and restart it with a broader bind:

```bash
./twn stop
TWN_TOOLKIT_HOST=0.0.0.0 ./twn start
```

The WiFi Ninja's Toolkit does not provide user authentication. Do not expose it directly to the
internet, and do not use a broad network bind on an untrusted network.
