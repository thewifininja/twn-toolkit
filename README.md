# FortiTool

A small Flask app for running repeatable FortiGate admin tasks against a user-defined appliance.

## What it does

- Stores local FortiGate connection profiles.
- Tests profile connectivity with the FortiGate monitor API.
- Bulk renames managed APs in the browser or from CSV.
- Bulk renames managed FortiSwitches in the browser or from CSV.
- Exports managed AP data to CSV.
- Exports managed FortiSwitch data to CSV.
- Exports wireless clients to CSV.
- Exports FortiSwitch clients to CSV.
- Provides a task registry so more CSV/API tasks can be added cleanly later.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app fortitool run --debug
```

Open http://127.0.0.1:5000.

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
For managed FortiSwitches, FortiTool detects whether the appliance exposes the
legacy writable `name` field or the FortiOS 7.4+ renameable `switch-id` key and
uses the matching update and read-back verification flow.

## Notes

API keys are stored locally in `instance/profiles.json`. Treat the machine running this app as trusted.

Default endpoint templates:

- APs: `/api/v2/cmdb/wireless-controller/wtp/{current_name}`
- Switches: `/api/v2/cmdb/switch-controller/managed-switch/{current_name}`
- Export AP Data: `/api/v2/cmdb/wireless-controller/wtp`
- Export Switch Data: `/api/v2/cmdb/switch-controller/managed-switch`
- Export Wireless Clients: `/api/v2/monitor/wifi/client`
- Export FortiSwitch Clients: `/api/v2/monitor/switch-controller/detected-device`

The endpoint template is editable before each run because FortiOS object paths can vary by version and feature set.
Some export tasks also have alternate endpoints; if a path returns 404, FortiTool tries the next candidate and updates the form with the endpoint that worked.

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
flask --app fortitool reset-data
```
