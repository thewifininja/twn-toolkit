from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.network_tools import ToolInputError, parse_ping_targets, subtract_subnets, validate_hosts


class NetworkToolTests(unittest.TestCase):
    def test_subtracts_ipv4_and_ipv6_networks(self) -> None:
        self.assertEqual(
            subtract_subnets(
                "10.0.0.0/24, 2001:db8::/126",
                "10.0.0.64/26, 2001:db8::/127",
            ),
            ["10.0.0.0/26", "10.0.0.128/25", "2001:db8::2/127"],
        )

    def test_rejects_shell_like_host_input(self) -> None:
        with self.assertRaises(ToolInputError):
            validate_hosts("127.0.0.1; whoami")

    def test_parses_optional_ping_target_names(self) -> None:
        self.assertEqual(
            parse_ping_targets("Core Router = 192.0.2.1\n8.8.8.8"),
            [
                {"label": "Core Router", "host": "192.0.2.1"},
                {"label": "", "host": "8.8.8.8"},
            ],
        )

    def test_tool_routes(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            response = client.post(
                "/tools/subnet-excluder",
                data={"supernets": "10.0.0.0/24", "exclusions": "10.0.0.64/26"},
            )
            self.assertIn(b"10.0.0.128/25", response.data)

            ping_result = {
                "host": "localhost",
                "reachable": True,
                "latency_ms": 0.1,
                "elapsed_ms": 1.0,
            }
            with patch("twn_toolkit.tools.ping_hosts", return_value=[ping_result]):
                response = client.post("/tools/ping/run", json={"hosts": "Localhost = localhost"})
            self.assertEqual(response.get_json()["results"], [{**ping_result, "label": "Localhost"}])

            response = client.post(
                "/tools/ping/profiles",
                json={
                    "name": "Office",
                    "hosts": "Gateway = 192.0.2.1\n8.8.8.8",
                    "interval": 5,
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["profile"]["targets"][0]["label"], "Gateway")
            self.assertIn(b"Office", client.get("/tools/ping").data)

            response = client.post(
                "/tools/ping/profiles",
                json={
                    "name": "Branches",
                    "original_name": "Office",
                    "hosts": "192.0.2.2",
                    "interval": 3,
                },
            )
            self.assertEqual(response.status_code, 200)
            ping_page = client.get("/tools/ping").data
            self.assertIn(b"Branches", ping_page)
            self.assertNotIn(b">Office</option>", ping_page)

            response = client.post("/tools/ping/profiles/delete", json={"name": "Branches"})
            self.assertEqual(response.get_json()["deleted"], "Branches")

            with patch(
                "twn_toolkit.tools.run_ssh_hosts",
                return_value=[{"host": "switch-1", "status": "success", "output": "ok"}],
            ):
                response = client.post(
                    "/tools/multi-ssh",
                    data={
                        "hosts": "switch-1",
                        "username": "admin",
                        "password": "not-rendered",
                        "port": "22",
                        "commands": "show version",
                        "confirm_execution": "on",
                    },
                )
            self.assertIn(b"ok", response.data)
            self.assertNotIn(b"not-rendered", response.data)


if __name__ == "__main__":
    unittest.main()
