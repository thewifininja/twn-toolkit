# Remote Terminal serial-console setup

Remote Terminal can open a persistent browser terminal directly to a serial
console adapter attached to the toolkit host. Quick Connect discovers USB
serial, local UART, and serial devices created by the operating system for an
already-paired Bluetooth adapter. Bluetooth pairing remains an operating-system
task.

Saved console connections use the adapter's hardware identity when available,
so a `/dev/ttyUSB0` or `/dev/cu.*` path change does not silently redirect the
record to a different device. The toolkit resolves the current path at connect
time. Only one active session may own a physical adapter, even when different
operators or web workers try to open it.

## Linux service permissions

Most distributions assign USB serial devices to `dialout`. Add the account that
runs the toolkit service to the device's actual group, then restart the service:

```bash
ls -l /dev/ttyUSB0
sudo usermod -aG dialout "$(id -un)"
./twn service restart
```

Use the group shown by `ls` when it is not `dialout`. Replugging the adapter may
also be necessary after changing group membership. Do not run the toolkit as
root merely to access a serial port.

## macOS

Remote Terminal prefers `/dev/cu.*` callout devices and hides the built-in
Bluetooth incoming and kernel debug endpoints. USB adapters normally appear as
`/dev/cu.usbserial-*`, `/dev/cu.usbmodem*`, or a vendor-specific callout name.

## Session and evidence behavior

Console sessions use the same tabs, pop-out view, reconnect scrollback,
Datastore save, and case transcript lifecycle as SSH and Telnet. Resizing the
browser terminal changes the local display but cannot negotiate a terminal size
over a raw serial line.

## Field Raspberry Pi workflow

The toolkit's existing startup automations cover address discovery; no separate
Discord-specific agent is required. Create an automation that runs **Once per
host boot**, add a Webhook/API action for the Discord webhook, and include
`{{toolkit.hostname}}`, `{{toolkit.primary_ipv4}}`, and
`{{toolkit.primary_url}}` in its message. The startup trigger waits for a usable
address before delivery. After opening the announced URL through an authorized
private path such as a VPN, use Remote Terminal → Console to reach the attached
switch. Do not expose the toolkit directly to the public Internet solely for
this workflow.
