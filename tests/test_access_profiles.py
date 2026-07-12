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
            self.assertIn(b"Command center", home.data)
            self.assertNotIn(b'/favorites/tools/fortigate.home', home.data)
            self.assertEqual(fortigate.status_code, 200)
            self.assertIn(b"Find Wireless Client History", fortigate.data)
            self.assertNotIn(b"Re-order Managed FortiSwitches", fortigate.data)

    def test_deleting_unassigned_access_profile_does_not_log_out_admin(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            setup_admin(client)
            store = AuthStore(instance)
            profile = store.save_access_profile(
                name="Temporary profile",
                tool_ids=["tools.ping"],
            )
            admin = store.get_user("admin")
            self.assertIsNotNone(admin)
            original_session_version = admin["session_version"]

            response = client.post(
                f"/settings/access-profiles/{profile['id']}/delete",
                follow_redirects=True,
            )

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Access profile deleted.", response.data)
            self.assertIn(b"Toolkit settings", response.data)
            updated_admin = store.get_user("admin")
            self.assertIsNotNone(updated_admin)
            self.assertEqual(updated_admin["session_version"], original_session_version)

    def test_deleting_assigned_access_profile_invalidates_affected_user(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            setup_admin(client)
            store = AuthStore(instance)
            profile = store.save_access_profile(
                name="Ping only",
                tool_ids=["tools.ping"],
            )
            user = store.create_user(
                "operator",
                "a different long password",
                access_profile_ids=[profile["id"]],
            )
            original_session_version = user["session_version"]

            client.post(f"/settings/access-profiles/{profile['id']}/delete")

            updated_user = store.get_user("operator")
            self.assertIsNotNone(updated_user)
            self.assertEqual(updated_user["access_profile_ids"], [])
            self.assertEqual(updated_user["session_version"], original_session_version + 1)


if __name__ == "__main__":
    unittest.main()
