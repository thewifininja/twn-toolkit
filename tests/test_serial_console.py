from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from twn_toolkit.serial_console import (
    SerialConsoleChannel,
    SerialConsoleError,
    list_serial_devices,
    open_serial_channel,
    resolve_serial_device,
    serial_settings,
)


class FakeSerial:
    def __init__(self) -> None:
        self.is_open = True
        self.in_waiting = 3
        self.timeout = 1
        self.writes: list[bytes] = []

    def read(self, size: int) -> bytes:
        self.in_waiting = 0
        return b"abc"[:size]

    def write(self, data: object) -> int:
        value = bytes(data)
        self.writes.append(value)
        return len(value)

    def close(self) -> None:
        self.is_open = False


class SerialConsoleTests(unittest.TestCase):
    def test_discovery_prefers_macos_callout_path_and_stable_usb_identity(self) -> None:
        common = {
            "description": "USB Serial",
            "product": "FTDI Adapter",
            "manufacturer": "FTDI",
            "serial_number": "ABC123",
            "hwid": "USB VID:PID=0403:6001 SER=ABC123",
            "vid": 0x0403,
            "pid": 0x6001,
            "location": "1-1",
        }
        ports = [
            SimpleNamespace(device="/dev/tty.usbserial-ABC", **common),
            SimpleNamespace(device="/dev/cu.usbserial-ABC", **common),
        ]
        with patch("twn_toolkit.serial_console.sys.platform", "darwin"), patch(
            "twn_toolkit.serial_console.os.access", return_value=True
        ):
            devices = list_serial_devices(ports)

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["path"], "/dev/cu.usbserial-ABC")
        self.assertEqual(devices[0]["transport"], "USB serial")
        self.assertTrue(devices[0]["id"].startswith("console_"))
        self.assertEqual(
            resolve_serial_device(devices[0]["id"], devices=devices)["path"],
            "/dev/cu.usbserial-ABC",
        )

    def test_invalid_settings_and_detached_devices_are_rejected(self) -> None:
        self.assertEqual(serial_settings(stop_bits=1.0)["stop_bits"], "1")
        with self.assertRaisesRegex(SerialConsoleError, "baud rate"):
            serial_settings(baud_rate=12345)
        with self.assertRaisesRegex(SerialConsoleError, "not currently attached"):
            resolve_serial_device("console_missing", devices=[])

    def test_channel_reads_writes_and_opens_with_serial_settings(self) -> None:
        connection = FakeSerial()
        channel = SerialConsoleChannel(connection)
        self.assertTrue(channel.recv_ready())
        self.assertEqual(channel.recv(10), b"abc")
        channel.sendall(b"show version\r")
        self.assertEqual(connection.writes, [b"show version\r"])
        channel.resize_pty(width=132, height=50)

        opened = FakeSerial()
        with patch("twn_toolkit.serial_console.serial.Serial", return_value=opened) as constructor:
            result = open_serial_channel(
                device_path="/dev/cu.usbserial-ABC",
                baud_rate=115200,
                data_bits=8,
                parity="none",
                stop_bits="1",
                flow_control="hardware",
            )
        self.assertIsInstance(result, SerialConsoleChannel)
        options = constructor.call_args.kwargs
        self.assertEqual(options["port"], "/dev/cu.usbserial-ABC")
        self.assertEqual(options["baudrate"], 115200)
        self.assertTrue(options["rtscts"])
        self.assertFalse(options["xonxoff"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
