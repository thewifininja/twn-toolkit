from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from twn_toolkit import create_app
from twn_toolkit.app import _switch_order_moves
from twn_toolkit.network_tools import (
    ToolInputError,
    parse_dns_servers,
    parse_ping_targets,
    parse_radius_attributes,
    subtract_subnets,
    validate_hosts,
)


class NetworkToolTests(unittest.TestCase):
    def test_builds_minimal_switch_order_moves(self) -> None:
        self.assertEqual(
            _switch_order_moves(
                ["switch-c", "switch-a", "switch-b"],
                ["switch-a", "switch-b", "switch-c"],
            ),
            [{"switch_id": "switch-c", "after": "switch-b"}],
        )
        self.assertEqual(
            _switch_order_moves(
                ["switch-c", "switch-b", "switch-a"],
                ["switch-a", "switch-b", "switch-c"],
            ),
            [
                {"switch_id": "switch-b", "after": "switch-a"},
                {"switch_id": "switch-c", "after": "switch-b"},
            ],
        )

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

    def test_parses_named_dns_servers_and_rejects_hostnames(self) -> None:
        self.assertEqual(
            parse_dns_servers("Cloudflare = 1.1.1.1\nGoogle IPv6 = 2001:4860:4860::8888"),
            [
                {"label": "Cloudflare", "address": "1.1.1.1"},
                {"label": "Google IPv6", "address": "2001:4860:4860::8888"},
            ],
        )
        with self.assertRaises(ToolInputError):
            parse_dns_servers("resolver.example.com")

    def test_parses_named_and_raw_radius_attributes(self) -> None:
        attributes = parse_radius_attributes(
            "NAS-Identifier = HQ-WLC\nNAS-IP-Address = 192.0.2.10\n#9:1 = 010203"
        )
        self.assertEqual(attributes[0]["name"], "NAS-Identifier")
        self.assertEqual(attributes[1]["value"], "192.0.2.10")
        self.assertEqual(
            attributes[2],
            {"name": "9:1", "value": "010203", "raw": True},
        )

    def test_tool_routes(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.config["TESTING"] = True
            client = app.test_client()

            self.assertIn(b"DNS Lookup Tester", client.get("/").data)
            home_page = client.get("/")
            self.assertIn(b"brand/dragon-mark-128.png", home_page.data)
            self.assertIn(b"brand/favicon-32.png", home_page.data)
            favicon = client.get("/favicon.ico")
            self.assertEqual(favicon.status_code, 200)
            self.assertEqual(favicon.mimetype, "image/png")
            favicon.close()
            self.assertIn(b"RADIUS Authentication Test", client.get("/").data)
            self.assertIn(b"Wi-Fi / LAN Speed Test", client.get("/").data)
            self.assertIn(b"Certificate Chain Inspector", client.get("/").data)
            self.assertIn(b"DHCP Discover", client.get("/").data)
            self.assertIn(b"Path MTU Tester", client.get("/").data)
            self.assertIn(b"Webhook / API Tester", client.get("/").data)
            self.assertIn(b"Syslog Tools", client.get("/").data)
            self.assertIn(b"Wi-Fi / LAN Speed Test", client.get("/tools/").data)
            self.assertIn(b"Certificate Chain Inspector", client.get("/tools/").data)
            self.assertEqual(client.get("/tools/certificate-inspector").status_code, 200)
            ip_page = client.get(
                "/tools/whats-my-ip",
                environ_base={"REMOTE_ADDR": "192.0.2.44"},
            )
            self.assertEqual(ip_page.status_code, 200)
            self.assertIn(b"192.0.2.44", ip_page.data)
            self.assertIn(b"IPv4", ip_page.data)
            self.assertIn(b"https://api64.ipify.org?format=json", ip_page.data)
            self.assertIn(b"Your public internet address", ip_page.data)
            self.assertIn(b'id="check-ip-again"', ip_page.data)
            self.assertIn("no-store", ip_page.headers["Cache-Control"])

            speed_page = client.get("/tools/speed-test")
            self.assertEqual(speed_page.status_code, 200)
            self.assertIn(b"browser and the machine running the toolkit", speed_page.data)
            self.assertIn(b'id="speed-download-meter"', speed_page.data)
            self.assertIn(b'id="speed-upload-meter"', speed_page.data)
            self.assertIn(b"<summary>Tools</summary>", speed_page.data)
            self.assertIn(b'href="/fortigate"', speed_page.data)
            self.assertIn(b'href="/fortiauthenticator"', speed_page.data)
            self.assertIn(b'href="/tools/"', speed_page.data.split(b"</nav>", 1)[0])

            latency_response = client.get("/tools/speed-test/ping")
            self.assertEqual(latency_response.status_code, 204)
            self.assertIn("no-store", latency_response.headers["Cache-Control"])

            download_response = client.get("/tools/speed-test/download?bytes=1025")
            self.assertEqual(download_response.status_code, 200)
            self.assertEqual(len(download_response.data), 1025)
            self.assertEqual(download_response.headers["Content-Length"], "1025")
            self.assertEqual(download_response.headers["Content-Encoding"], "identity")
            self.assertEqual(
                client.get("/tools/speed-test/download?bytes=0").status_code,
                400,
            )

            upload_response = client.post(
                "/tools/speed-test/upload",
                data=b"x" * 4097,
                content_type="application/octet-stream",
            )
            self.assertEqual(upload_response.status_code, 200)
            self.assertEqual(upload_response.get_json()["bytes_received"], 4097)
            self.assertEqual(
                client.post(
                    "/tools/speed-test/upload",
                    data=b"",
                    content_type="application/octet-stream",
                ).status_code,
                411,
            )

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

            response = client.post(
                "/tools/dns-response/profiles/hosts",
                data={"profile_name": "Public sites", "values": "Example = example.com"},
            )
            self.assertEqual(response.status_code, 200)
            response = client.post(
                "/tools/dns-response/profiles/servers",
                data={"profile_name": "Public DNS", "values": "Cloudflare = 1.1.1.1"},
            )
            self.assertEqual(response.status_code, 200)
            page = client.get("/tools/dns-response")
            self.assertIn(b"Public sites", page.data)
            self.assertIn(b"Public DNS", page.data)

            dns_result = {
                "host": "example.com",
                "host_label": "Example",
                "server": "1.1.1.1",
                "server_label": "Cloudflare",
                "record_type": "A",
                "status": "success",
                "answers": ["192.0.2.10"],
                "response_ms": 12.3,
            }
            with patch("twn_toolkit.tools.dns_lookup_matrix", return_value=[dns_result]):
                response = client.post(
                    "/tools/dns-response",
                    data={
                        "hosts": "Example = example.com",
                        "servers": "Cloudflare = 1.1.1.1",
                        "record_type": "A",
                        "timeout": "3",
                    },
                )
            self.assertIn(b"192.0.2.10", response.data)
            self.assertIn(b"12.3 ms", response.data)

            response = client.post(
                "/tools/radius-test/profiles/servers",
                data={
                    "name": "Primary RADIUS",
                    "host": "192.0.2.40",
                    "port": "1812",
                    "secret": "shared-secret-not-rendered",
                },
            )
            self.assertEqual(response.status_code, 200)
            response = client.post(
                "/tools/radius-test/profiles/credentials",
                data={
                    "name": "Test User",
                    "username": "radius-test",
                    "password": "password-not-rendered",
                },
            )
            self.assertEqual(response.status_code, 200)
            response = client.post(
                "/tools/radius-test/profiles/attributes",
                data={
                    "name": "HQ WLAN",
                    "attributes": "NAS-Identifier = HQ-WLC\nNAS-IP-Address = 192.0.2.10",
                },
            )
            self.assertEqual(response.status_code, 200)
            radius_page = client.get("/tools/radius-test").data
            self.assertIn(b"Primary RADIUS", radius_page)
            self.assertIn(b"Test User", radius_page)
            self.assertIn(b"HQ WLAN", radius_page)
            self.assertNotIn(b"shared-secret-not-rendered", radius_page)
            self.assertNotIn(b"password-not-rendered", radius_page)
            with patch("twn_toolkit.tools.platform.system", return_value="Darwin"):
                mac_radius_page = client.get("/tools/radius-test").data
            self.assertIn(b"macOS EAP compatibility", mac_radius_page)
            self.assertIn(b'class="platform-warning"', mac_radius_page)
            self.assertIn(b"standard Homebrew formula", mac_radius_page)

            response = client.post(
                "/tools/radius-test/profiles/servers",
                data={
                    "original_name": "Primary RADIUS",
                    "name": "Primary RADIUS",
                    "host": "192.0.2.41",
                    "port": "1812",
                    "secret": "",
                },
            )
            self.assertEqual(response.status_code, 200)
            radius_page = client.get("/tools/radius-test").data
            self.assertIn(b"192.0.2.41", radius_page)
            self.assertNotIn(b"shared-secret-not-rendered", radius_page)

            radius_result = {
                "server_name": "Primary RADIUS",
                "server": "192.0.2.40",
                "port": 1812,
                "status": "Access-Accept",
                "response_ms": 8.4,
                "attributes": [{"name": "Reply-Message", "value": "Welcome"}],
            }
            with patch("twn_toolkit.tools.radius_authenticate", return_value=[radius_result]) as auth:
                response = client.post(
                    "/tools/radius-test",
                    data={
                        "server_names": "Primary RADIUS",
                        "credential_name": "Test User",
                        "protocol": "pap",
                        "timeout": "3",
                        "retries": "1",
                        "attribute_profile": "HQ WLAN",
                    },
                )
            self.assertIn(b"Access-Accept", response.data)
            self.assertIn(b"Reply-Message", response.data)
            self.assertNotIn(b"password-not-rendered", response.data)
            auth.assert_called_once()

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
