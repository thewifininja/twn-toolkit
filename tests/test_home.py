from __future__ import annotations

import tempfile
import unittest

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.auth import AuthStore
from twn_toolkit.dashboard_layout import DashboardLayoutStore


class HomePageTests(unittest.TestCase):
    def assert_sidebar_section_open(self, html: str, label: str) -> None:
        label_index = html.index(f"<span>{label}</span>")
        section_index = html.rfind('<details class="side-nav-section"', 0, label_index)
        self.assertNotEqual(section_index, -1)
        section_tag = html[section_index : html.index(">", section_index)]
        self.assertIn("open", section_tag)

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
        self.assertIn(b"Command center", response.data)
        self.assertIn(b"A live-ish pulse", response.data)
        self.assertIn(b"Recent activity", response.data)
        self.assertIn(b"Favorites", response.data)
        self.assertIn(b"User scoreboard", response.data)
        self.assertIn(b"DNS", response.data)
        self.assertIn(b"Speed tests", response.data)
        self.assertIn(b"Syslog", response.data)
        self.assertIn(b"v0.8.0", response.data)
        self.assertIn(b'href="/help"', response.data)
        self.assertIn(b"Packet Replay", response.data)
        self.assertIn(b"FortiGate", response.data)
        self.assertNotIn(b"Find Wireless Client History", response.data)
        self.assertNotIn(b"Re-order Managed FortiSwitches", response.data)

    def test_help_page_renders_user_guidance(self) -> None:
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

            response = client.get("/help")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Using The WiFi Ninja", response.data)
        self.assertIn(b"Profiles, secrets, and backups", response.data)
        self.assertIn(b"Packet Replay", response.data)
        self.assertIn(b"Conditions, actions, and automations", response.data)
        self.assertIn(b"Home FortiGate = gate.example.com | 8443", response.data)
        self.assertIn(b"Syslog notification action", response.data)
        self.assertIn(b"./twn fix-permissions", response.data)
        self.assertIn(b"Dashboard and metrics", response.data)
        self.assertIn(b"Release notes", response.data)
        self.assertIn(b"v0.8.0", response.data)
        self.assertIn(b"Operational dashboard and automation milestone", response.data)
        self.assertIn(b"Use at your own risk", response.data)

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

    def test_sidebar_opens_current_self_service_sections(self) -> None:
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

            fortigate = client.get("/fortigate").data.decode()
            fortiauthenticator = client.get("/fortiauthenticator").data.decode()
            settings = client.get("/settings").data.decode()

        self.assert_sidebar_section_open(fortigate, "Fortinet Tools")
        self.assertIn('side-nav-parent-link active" href="/fortigate"', fortigate)
        self.assert_sidebar_section_open(fortiauthenticator, "Fortinet Tools")
        self.assertIn(
            'side-nav-parent-link active" href="/fortiauthenticator"',
            fortiauthenticator,
        )
        self.assert_sidebar_section_open(settings, "Administration")
        self.assertIn('active" href="/settings"', settings)
        self.assertNotIn('/favorites/tools/admin.settings', settings)

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
            remove = client.post(
                "/favorites/tools/tools.packet_replay",
                data={"next": "/"},
            )
            updated_user = AuthStore(instance).get_user("admin")
            updated_page = client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertIn("tools.packet_replay", user["favorite_tools"])
        self.assertIn(b"Packet Replay", page.data)
        self.assertIn(b"Favorites", page.data)
        self.assertIn(b"side-nav-favorite-button active", page.data)
        self.assertIn(b"Remove Packet Replay from favorites", page.data)
        self.assertEqual(remove.status_code, 302)
        self.assertNotIn("tools.packet_replay", updated_user["favorite_tools"])
        self.assertIn(b"Add Packet Replay to favorites", updated_page.data)

    def test_dashboard_renders_activity_and_admin_can_reset_metric(self) -> None:
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
            ActivityStore(instance).record_event(
                "Reachability",
                "Ran ping test",
                "5 probes sent",
                counters={"ping": {"probes_sent": 5, "replies_received": 4}},
                user_id="admin-id",
                username="admin",
                count_action=True,
            )

            page = client.get("/")
            reset = client.post("/activity/reset/ping", data={"next": "/"})
            reset_page = client.get("/")

        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Ran ping test", page.data)
        self.assertIn(b"5 probes sent", page.data)
        self.assertIn(b"admin", page.data)
        self.assertIn(b"1 action", page.data)
        self.assertIn(b"Rank by", page.data)
        self.assertIn(b"Ping probes sent", page.data)
        self.assertIn(b"5 sent", page.data)
        self.assertIn(b"4 replies", page.data)
        self.assertEqual(reset.status_code, 302)
        self.assertIn(b">0</span>", reset_page.data)

    def test_admin_can_reorder_and_hide_dashboard_widgets(self) -> None:
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
            original = ActivityStore(instance).summary()["cards"]
            metric_ids = [card["metric"] for card in original]
            response = client.post(
                "/dashboard/layout",
                data={
                    "order": ",".join(reversed(metric_ids)),
                    "hidden": metric_ids[0],
                },
            )
            page = client.get("/")
            saved = DashboardLayoutStore(instance).get(metric_ids)
            AuthStore(instance).create_user(
                "operator", "correct horse battery staple"
            )
            operator = app.test_client()
            operator.post(
                "/login",
                data={
                    "username": "operator",
                    "password": "correct horse battery staple",
                },
            )
            operator_page = operator.get("/")
            forbidden = operator.post(
                "/dashboard/layout",
                data={"order": ",".join(metric_ids), "hidden": ""},
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(saved["hidden"], [metric_ids[0]])
        self.assertEqual(saved["order"][-1], metric_ids[0])
        self.assertIn(b"Edit dashboard", page.data)
        self.assertIn(b"Save layout", page.data)
        self.assertIn(b"Hidden widgets", page.data)
        self.assertIn(
            f'data-widget-id="{metric_ids[0]}" data-widget-hidden="true" hidden'.encode(),
            page.data,
        )
        self.assertNotIn(
            f'data-widget-id="{metric_ids[0]}"'.encode(), operator_page.data
        )
        self.assertNotIn(b"Edit dashboard", operator_page.data)
        self.assertEqual(forbidden.status_code, 403)

    def test_dashboard_layout_store_appends_new_widgets_and_reset_restores_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            store = DashboardLayoutStore(instance)
            store.save(["two", "one"], ["one"], ["one", "two"])
            expanded = store.get(["one", "two", "three"])
            self.assertEqual(expanded["order"], ["two", "three", "one"])
            self.assertEqual(expanded["hidden"], ["one"])
            store.reset()
            self.assertEqual(
                store.get(["one", "two", "three"])["order"],
                ["one", "two", "three"],
            )

    def test_dashboard_can_rank_scoreboard_by_metric(self) -> None:
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
            store = ActivityStore(instance)
            store.record_event(
                "Fortinet",
                "API",
                counters={"fortinet": {"api_calls": 12}},
                user_id="api-id",
                username="api-user",
                count_action=True,
            )
            store.record_event(
                "Reachability",
                "Ping",
                counters={"ping": {"probes_sent": 30}},
                user_id="ping-id",
                username="ping-user",
                count_action=True,
            )

            page = client.get("/?scoreboard_rank=ping.probes_sent")

        self.assertLess(page.data.index(b"ping-user"), page.data.index(b"api-user"))
        self.assertIn(b'<option value="ping.probes_sent" selected', page.data)
        self.assertEqual(page.data.count(b'<details class="scoreboard-entry">'), 2)
        self.assertNotIn(b'<details class="scoreboard-entry" open', page.data)
        self.assertIn(b"Ping probes sent", page.data)
        self.assertIn(b"Activity score", page.data)

    def test_admin_can_clear_user_scores_and_all_scores(self) -> None:
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
            store = ActivityStore(instance)
            store.record_event("Test", "Admin action", user_id="admin-id", username="admin", count_action=True)
            store.record_event("Test", "Tech action", user_id="tech-id", username="tech", count_action=True)

            page = client.get("/")
            clear_one = client.post(
                "/activity/scoreboard/users/tech-id/reset",
                data={"next": "/"},
            )
            after_one = client.get("/")
            clear_all = client.post("/activity/scoreboard/reset", data={"next": "/"})
            after_all = client.get("/")

        self.assertIn(b"Clear all scores", page.data)
        self.assertIn(b"Clear score", page.data)
        self.assertEqual(clear_one.status_code, 302)
        self.assertIn(b"admin", after_one.data)
        self.assertNotIn(b"tech</strong>", after_one.data)
        self.assertEqual(clear_all.status_code, 302)
        self.assertIn(b"No user activity yet", after_all.data)

    def test_dashboard_recent_activity_display_is_capped(self) -> None:
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
            store = ActivityStore(instance)
            for index in range(10):
                store.record_event("Test", f"Activity {index}", user_id="admin", username="admin")

            page = client.get("/")

        self.assertIn(b"Showing the latest 8 of 10 events from lifetime", page.data)
        self.assertIn(b"Activity 9", page.data)
        self.assertIn(b"Activity 2", page.data)
        self.assertNotIn(b"Activity 1", page.data)

    def test_dashboard_time_window_is_selectable_and_preserved_for_ranking(self) -> None:
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
            ActivityStore(instance).record_event(
                "Reachability",
                "Ping",
                counters={"ping": {"probes_sent": 3}},
                user_id="admin",
                username="admin",
                count_action=True,
            )

            page = client.get(
                "/?activity_window=hour&scoreboard_rank=ping.probes_sent"
            )

        self.assertIn(b'<option value="hour" selected', page.data)
        self.assertIn(b'name="activity_window" value="hour"', page.data)
        self.assertIn(b"Metrics, scoreboard, and recent activity", page.data)

    def test_dashboard_custom_range_renders_and_is_preserved_for_ranking(self) -> None:
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
            ActivityStore(instance).record_event(
                "Reachability",
                "Ping",
                counters={"ping": {"probes_sent": 3}},
                user_id="admin",
                username="admin",
                count_action=True,
            )

            page = client.get(
                "/",
                query_string={
                    "activity_window": "custom",
                    "activity_start": "2026-07-09T08:00:00",
                    "activity_end": "2026-07-09T17:00:00",
                    "scoreboard_rank": "ping.probes_sent",
                },
            )

        self.assertIn(b'<option value="custom" selected', page.data)
        self.assertIn(b'id="activity-start" type="datetime-local"', page.data)
        self.assertIn(b'value="2026-07-09T08:00:00"', page.data)
        self.assertIn(b'value="2026-07-09T17:00:00"', page.data)
        self.assertIn(b"Apply range", page.data)


if __name__ == "__main__":
    unittest.main()
