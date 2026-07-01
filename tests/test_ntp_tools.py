from __future__ import annotations

import socket
import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.network_tools import ToolInputError
from twn_toolkit.ntp_tools import NTP_PACKET, _unix_to_ntp, test_ntp_server


class FakeSocket:
    def __init__(self, response: bytes):
        self.response = response
        self.request = b""

    def settimeout(self, _timeout):
        pass

    def sendto(self, request, _address):
        self.request = request

    def recvfrom(self, _size):
        request_transmit = NTP_PACKET.unpack(self.request)[-1]
        values = list(NTP_PACKET.unpack(self.response))
        values[8] = request_transmit
        return NTP_PACKET.pack(*values), ("192.0.2.123", 123)

    def close(self):
        pass


class NTPToolTests(unittest.TestCase):
    def _response(self) -> bytes:
        reference = _unix_to_ntp(1_699_999_000.0)
        received = _unix_to_ntp(1_700_000_000.020)
        transmitted = _unix_to_ntp(1_700_000_000.021)
        return NTP_PACKET.pack(
            0x24,
            2,
            6,
            -20,
            int(0.010 * 65536),
            int(0.005 * 65536),
            socket.inet_aton("192.0.2.1"),
            reference,
            0,
            received,
            transmitted,
        )

    def test_calculates_ntp_timing_and_metadata(self) -> None:
        fake = FakeSocket(self._response())
        with (
            patch(
                "twn_toolkit.ntp_tools.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.123", 123))],
            ),
            patch("twn_toolkit.ntp_tools.socket.socket", return_value=fake),
            patch("twn_toolkit.ntp_tools.time.time", side_effect=[1_700_000_000.0, 1_700_000_000.040]),
        ):
            result = test_ntp_server("ntp.example", samples=1)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["stratum"], 2)
        self.assertEqual(result["reference_id"], "192.0.2.1")
        self.assertTrue(result["synchronized"])
        self.assertAlmostEqual(result["offset_ms"], 0.5, places=2)
        self.assertAlmostEqual(result["delay_ms"], 39.0, places=2)

    def test_validates_settings(self) -> None:
        with self.assertRaises(ToolInputError):
            test_ntp_server("", samples=1)
        with self.assertRaises(ToolInputError):
            test_ntp_server("ntp.example", port=0)
        with self.assertRaises(ToolInputError):
            test_ntp_server("ntp.example", samples=11)

    def test_route_renders_result(self) -> None:
        result = {
            "host": "ntp.example",
            "port": 123,
            "resolved_address": "192.0.2.123",
            "status": "success",
            "successful_samples": 1,
            "total_samples": 1,
            "offset_ms": 0.5,
            "delay_ms": 10.2,
            "jitter_ms": 0.0,
            "stratum": 2,
            "version": 4,
            "leap": 0,
            "leap_text": "No warning",
            "reference_id": "192.0.2.1",
            "reference_time": "2023-11-14T00:00:00.000Z",
            "root_delay_ms": 2.0,
            "root_dispersion_ms": 1.0,
            "precision_seconds": 0.000001,
            "synchronized": True,
            "samples": [
                {
                    "status": "success",
                    "offset_ms": 0.5,
                    "delay_ms": 10.2,
                    "server_time": "2023-11-14T00:00:01.000Z",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            with patch("twn_toolkit.tools.test_ntp_server", return_value=result):
                response = app.test_client().post(
                    "/tools/ntp-test",
                    data={"host": "ntp.example", "port": "123", "timeout": "3", "samples": "1"},
                )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Clock offset", response.data)
        self.assertIn(b"+0.500 ms", response.data)


if __name__ == "__main__":
    unittest.main()
