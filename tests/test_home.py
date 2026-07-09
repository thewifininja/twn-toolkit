from __future__ import annotations

import tempfile
import unittest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore


class HomePageTests(unittest.TestCase):
    def test_home_renders_launchpad_and_packet_replay_for_admin(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )

            response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"What are we fixing today?", response.data)
        self.assertIn(b"Tool Categories", response.data)
        self.assertIn(b"Favorites", response.data)
        self.assertIn(b"Tool Areas", response.data)
        self.assertIn(b"Packet Replay", response.data)
        self.assertIn(b"FortiGate", response.data)
        self.assertNotIn(b"Bulk Rename APs", response.data)
        self.assertNotIn(b"Find Wireless Client History", response.data)
        self.assertNotIn(b"Re-order Managed FortiSwitches", response.data)

    def test_fortinet_pages_show_workflows_without_self_profile_card(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )

            fortigate = client.get("/fortigate")
            fortiauthenticator = client.get("/fortiauthenticator")

        self.assertEqual(fortigate.status_code, 200)
        self.assertIn(b"These workflows use the FortiGate profiles", fortigate.data)
        self.assertIn(b"Bulk Rename APs", fortigate.data)
        self.assertIn(b"Find Wireless Client History", fortigate.data)
        self.assertIn(b"Re-order Managed FortiSwitches", fortigate.data)
        self.assertNotIn(b"Fortinet Workflows", fortigate.data)
        self.assertNotIn(b"Profiles, FortiAP/FortiSwitch workflows", fortigate.data)
        self.assertEqual(fortiauthenticator.status_code, 200)
        self.assertIn(
            b"These workflows use the FortiAuthenticator profiles",
            fortiauthenticator.data,
        )
        self.assertIn(b"MAC Device Cleanup", fortiauthenticator.data)
        self.assertNotIn(b"Profiles and MAC device administration workflows.", fortiauthenticator.data)

    def test_fortigate_profile_test_uses_loading_animation(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )
            client.post(
                "/profiles",
                data={
                    "name": "Lab",
                    "host": "https://fortigate.example",
                    "api_key": "secret",
                    "default_vdom": "root",
                },
            )

            response = client.get("/fortigate")

        self.assertIn(b"Testing FortiGate profile", response.data)

    def test_user_can_toggle_homepage_favorite(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            client = app.test_client()
            client.post(
                "/setup",
                data={
                    "username": "admin",
                    "password": "correct horse battery staple",
                    "confirm_password": "correct horse battery staple",
                },
            )

            response = client.post(
                "/favorites/tools/tools.packet_replay",
                data={"next": "/"},
            )
            user = AuthStore(instance).get_user("admin")
            page = client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertIn("tools.packet_replay", user["favorite_tools"])
        self.assertIn(b"Remove Packet Replay from favorites", page.data)


if __name__ == "__main__":
    unittest.main()
