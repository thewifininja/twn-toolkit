from __future__ import annotations

import tempfile
import unittest
from io import BytesIO

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore
from twn_toolkit.datastore import LocalDatastore


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
    def test_admin_can_duplicate_an_access_profile(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            setup_admin(client)
            store = AuthStore(instance)
            source = store.save_access_profile(
                name="Network operators",
                description="Routine diagnostics",
                tool_ids=["tools.ping", "tools.traceroute"],
            )

            response = client.post(
                f"/settings/access-profiles/{source['id']}/duplicate"
            )

            self.assertEqual(response.status_code, 302)
            copied = next(
                profile
                for profile in store.access_profiles()
                if profile["name"] == "Network operators copy"
            )
            self.assertNotEqual(copied["id"], source["id"])
            self.assertEqual(copied["description"], source["description"])
            self.assertEqual(copied["tool_ids"], source["tool_ids"])

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
            self.assertIn(b">Ping</span>", home.data)
            self.assertNotIn(b"DNS Tester", home.data)

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

    def test_packet_replay_requires_datastore_access_to_list_stored_captures(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            setup_admin(client)
            LocalDatastore(instance).save_upload(
                "", "private-capture.pcap", BytesIO(b"pcap contents")
            )
            store = AuthStore(instance)
            profile = store.save_access_profile(
                name="Packet replay only",
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

            page = client.get("/tools/packet-replay")
            crafted_request = client.post(
                "/tools/packet-replay",
                data={
                    "datastore_capture": "private-capture.pcap",
                    "vlan_action": "keep",
                    "repeat_count": "1",
                    "interval_seconds": "1",
                    "action": "preview",
                },
            )

            self.assertEqual(page.status_code, 200)
            self.assertNotIn(b"private-capture.pcap", page.data)
            self.assertIn(b"Add Datastore to this account", page.data)
            self.assertIn(b"Datastore access is required", crafted_request.data)

            datastore_profile = store.save_access_profile(
                name="Packet replay with datastore",
                tool_ids=["tools.packet_replay", "local.datastore"],
            )
            store.create_user(
                "replayreader",
                "another different long password",
                access_profile_ids=[datastore_profile["id"]],
            )
            client.post("/logout")
            client.post(
                "/login",
                data={
                    "username": "replayreader",
                    "password": "another different long password",
                },
            )
            authorized_page = client.get("/tools/packet-replay")
            self.assertIn(b"private-capture.pcap", authorized_page.data)

    def test_packet_capture_only_user_cannot_browse_or_save_datastore_pcaps(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance)
            client = app.test_client()
            setup_admin(client)
            store = AuthStore(instance)
            profile = store.save_access_profile(
                name="Packet capture only",
                tool_ids=["tools.packet_capture"],
            )
            store.create_user(
                "captureuser",
                "a different long password",
                access_profile_ids=[profile["id"]],
            )

            client.post("/logout")
            client.post(
                "/login",
                data={"username": "captureuser", "password": "a different long password"},
            )

            page = client.get("/tools/packet-capture")
            self.assertEqual(page.status_code, 200)
            self.assertNotIn(b"Stored packet captures", page.data)
            self.assertEqual(
                client.get(
                    "/local/datastore/view-pcap",
                    query_string={"path": "capture.pcap"},
                ).status_code,
                403,
            )
            self.assertEqual(
                client.post(
                    "/tools/packet-capture/missing/save",
                    data={"destination": ""},
                ).status_code,
                403,
            )

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
            self.assertIn(b"Operator workspace", home.data)
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
            self.assertIn(b"System settings", response.data)
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
