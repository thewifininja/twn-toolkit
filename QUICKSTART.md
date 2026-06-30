# The WiFi Ninja's Toolkit Quick Start

## Requirements

- Python 3.10 or newer
- Network access to the FortiGate management interface
- A FortiGate REST API administrator and token

A read-only API profile is sufficient for exports. Rename tasks require
read-write permission for the wireless-controller or switch-controller resource.

## Install

From the project folder:

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Start

```bash
flask --app twn_toolkit run
```

Open <http://127.0.0.1:5000>.

Keep the terminal open while using The WiFi Ninja's Toolkit. Press `Ctrl+C` to stop it.

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

## Network Tools

The **Network Tools** workspace does not use FortiGate profiles.

- **Subnet Excluder** subtracts comma-, space-, or line-separated CIDRs from
  parent networks. Enter `rfc1918` to use all private IPv4 ranges.
- **Multi-Host Ping** runs repeated ICMP checks from the machine hosting
  The WiFi Ninja's Toolkit. Host collections can be saved as profiles, and
  optional friendly names use `Name = host`. Select **Stop** to end polling.
- **Multi-SSH** sends the same command sequence to multiple devices using an
  interactive SSH shell. Passwords are used only for the current request and
  are not saved. Unknown host keys are rejected unless explicitly allowed.

Multi-SSH commands execute on real devices. Review the host list and commands
carefully before selecting the required execution confirmation.

## Reset Before Sharing

The WiFi Ninja's Toolkit persists FortiGate profiles, API keys, and saved ping
profiles. To remove them:

```bash
flask --app twn_toolkit reset-data
```

Confirm the prompt. For scripts or packaging:

```bash
flask --app twn_toolkit reset-data --yes
```

This removes `instance/profiles.json` and `instance/ping_profiles.json`; it does
not modify the application code.
The `instance/` and `.venv/` directories are excluded by `.gitignore`.

After resetting, share the project without `.venv/`, `.git/`, or `instance/`.
The recipient can follow this guide to create their own environment and profile.

## Local Network Access

To intentionally allow another machine on the same trusted network to connect:

```bash
flask --app twn_toolkit run --host 0.0.0.0
```

The WiFi Ninja's Toolkit does not provide user authentication. Do not expose it directly to the
internet, and do not use a broad network bind on an untrusted network.
