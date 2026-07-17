from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.audit import AuditStore
from twn_toolkit.network_tools import ToolInputError, parse_tcp_ports, scan_tcp_ports


class PortScannerTests(unittest.TestCase):
    def test_parses_ports_ranges_and_deduplicates(self) -> None:
        self.assertEqual(parse_tcp_ports("443, 80, 8000-8002, 443"), [80, 443, 8000, 8001, 8002])
        with self.assertRaises(ToolInputError):
            parse_tcp_ports("9000-8000")
        with self.assertRaises(ToolInputError):
            parse_tcp_ports("0, 443")

    def test_scans_and_preserves_target_port_order(self) -> None:
        class OpenSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        def connect(address, timeout):
            if address[1] == 22:
                return OpenSocket()
            raise ConnectionRefusedError

        with patch("twn_toolkit.network_tools.socket.create_connection", side_effect=connect):
            results = scan_tcp_ports(
                [{"label": "Switch", "host": "192.0.2.10"}],
                [22, 443],
                timeout=0.5,
                max_workers=2,
            )
        self.assertEqual([result["port"] for result in results], [22, 443])
        self.assertEqual([result["status"] for result in results], ["open", "closed"])

    def test_rejects_unbounded_scan_matrix(self) -> None:
        targets = [{"label": "", "host": f"host-{index}.example"} for index in range(26)]
        with self.assertRaises(ToolInputError):
            scan_tcp_ports(targets, list(range(1, 201)))

    def test_profile_crud_and_scan_route(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            page = client.get("/tools/port-scanner")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"TCP Port Scanner", page.data)

            response = client.post(
                "/tools/port-scanner/profiles/hosts",
                data={
                    "name": "Lab",
                    "values": "Core = 192.0.2.10-192.0.2.11\nserver.example.com",
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["profile"]["count"], 3)

            response = client.post(
                "/tools/port-scanner/profiles/ports",
                data={"name": "Web", "values": "80, 443, 8000-8002"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["profile"]["count"], 5)
            page = client.get("/tools/port-scanner")
            self.assertIn(b"Lab", page.data)
            self.assertIn(b"Web", page.data)

            fake_results = [
                {
                    "host": "192.0.2.10",
                    "label": "Core",
                    "port": 443,
                    "service": "https",
                    "status": "open",
                    "detail": "",
                    "elapsed_ms": 4.2,
                },
                {
                    "host": "192.0.2.10",
                    "label": "Core",
                    "port": 8443,
                    "service": "",
                    "status": "closed",
                    "detail": "Connection refused",
                    "elapsed_ms": 1.1,
                },
            ]
            with patch("twn_toolkit.port_scanner_routes.scan_tcp_ports", return_value=fake_results):
                response = client.post(
                    "/tools/port-scanner",
                    data={
                        "hosts": "Core = 192.0.2.10",
                        "ports": "443, 8443",
                        "timeout": "1",
                        "concurrency": "20",
                        "open_only": "on",
                    },
                )
            self.assertIn(b"https", response.data)
            self.assertIn(b"4.2 ms", response.data)
            self.assertNotIn(b"Connection refused", response.data)
            summary = ActivityStore(instance).summary()
            self.assertEqual(summary["counters"]["tcp"]["ports_scanned"], 2)
            self.assertEqual(summary["counters"]["actions"]["total"], 1)

            response = client.post(
                "/tools/port-scanner/profiles/ports/delete",
                data={"name": "Web"},
            )
            self.assertEqual(response.status_code, 200)
            event = AuditStore(instance).recent(1)[0]
            self.assertEqual(event["action"], "tcp_scanner.ports.profile_deleted")
            self.assertEqual(event["resource_name"], "Web")
            self.assertEqual(event["details"]["profile type"], "TCP scanner port profile")


if __name__ == "__main__":
    unittest.main()
