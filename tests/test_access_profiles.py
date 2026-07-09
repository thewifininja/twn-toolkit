from __future__ import annotations

import tempfile
import unittest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore


def setup_admin(client) -> None:
    client.post(
        "/setup",
        data={
            "username": "admin",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        },
    )


class AccessProfileTests(unittest.TestCase):
    def test_admin_can_create_custom_access_profile_and_assign_to_user(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            setup_admin(client)

            response = client.post(
                "/settings/access-profiles",
                data={
                    "name": "Ping only",
                    "description": "Can run multi-host ping",
                    "tool_id": ["tools.ping", "admin.settings", "not-a-real-tool"],
                },
            )
            store = AuthStore(instance)
            profiles = store.access_profiles()
            self.assertEqual(response.status_code, 302)
            self.assertEqual(len(profiles), 1)
            self.assertEqual(profiles[0]["tool_ids"], ["tools.ping"])

            client.post(
                "/settings/users",
                data={
                    "username": "operator",
                    "password": "a different long password",
                    "confirm_password": "a different long password",
                    "access_profile_id": profiles[0]["id"],
                },
            )
            operator = store.get_user("operator")
            self.assertIsNotNone(operator)
            self.assertFalse(operator["is_admin"])
            self.assertEqual(operator["access_profile_ids"], [profiles[0]["id"]])

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "operator", "password": "a different long password"},
            )

            self.assertEqual(client.get("/tools/ping").status_code, 200)
            self.assertEqual(client.get("/tools/dns-response").status_code, 403)
            home = client.get("/")
            self.assertIn(b"Multi-Host Ping", home.data)
            self.assertNotIn(b"DNS Lookup Tester", home.data)

    def test_access_profile_can_grant_high_risk_tool_without_admin_status(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            setup_admin(client)
            store = AuthStore(instance)
            profile = store.save_access_profile(
                name="Packet replay",
                tool_ids=["tools.packet_replay"],
            )
            store.create_user(
                "packetuser",
                "a different long password",
                access_profile_ids=[profile["id"]],
            )

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "packetuser", "password": "a different long password"},
            )

            self.assertEqual(client.get("/tools/packet-replay").status_code, 200)
            self.assertEqual(client.get("/settings/backup").status_code, 403)

    def test_nav_and_home_only_show_allowed_categories(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            setup_admin(client)
            store = AuthStore(instance)
            profile = store.save_access_profile(
                name="Wireless history",
                tool_ids=["fortigate.wireless_client_history"],
            )
            store.create_user(
                "wirelessuser",
                "a different long password",
                access_profile_ids=[profile["id"]],
            )

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "wirelessuser", "password": "a different long password"},
            )
            home = client.get("/")
            fortigate = client.get("/fortigate")

            self.assertEqual(home.status_code, 200)
            self.assertIn(b'href="/fortigate"', home.data)
            self.assertNotIn(b'href="/fortiauthenticator"', home.data)
            self.assertNotIn(b'href="/tools/"', home.data)
            self.assertIn(b"FortiGate / FortiAP / FortiSwitch", home.data)
            self.assertEqual(fortigate.status_code, 200)
            self.assertIn(b"Find Wireless Client History", fortigate.data)
            self.assertNotIn(b"Re-order Managed FortiSwitches", fortigate.data)


if __name__ == "__main__":
    unittest.main()
