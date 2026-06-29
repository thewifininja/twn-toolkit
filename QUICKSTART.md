# FortiTool Quick Start

## Requirements

- Python 3.10 or newer
- Network access to the FortiGate management interface
- A FortiGate REST API administrator and token

A read-only API profile is sufficient for exports. Rename tasks require
read-write permission for the wireless-controller or switch-controller resource.

## Install

From the FortiTool folder:

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
flask --app fortitool run
```

Open <http://127.0.0.1:5000>.

Keep the terminal open while using FortiTool. Press `Ctrl+C` to stop it.

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
**Apply These Changes** to perform the live updates. FortiTool reads each object
back after an update and reports whether the requested name was verified.

## Reset Before Sharing

FortiTool currently persists only saved profiles and API keys. To remove them:

```bash
flask --app fortitool reset-data
```

Confirm the prompt. For scripts or packaging:

```bash
flask --app fortitool reset-data --yes
```

This removes `instance/profiles.json`; it does not modify the application code.
The `instance/` and `.venv/` directories are excluded by `.gitignore`.

After resetting, share the project without `.venv/`, `.git/`, or `instance/`.
The recipient can follow this guide to create their own environment and profile.

## Local Network Access

To intentionally allow another machine on the same trusted network to connect:

```bash
flask --app fortitool run --host 0.0.0.0
```

FortiTool does not provide user authentication. Do not expose it directly to the
internet, and do not use a broad network bind on an untrusted network.
