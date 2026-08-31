from __future__ import annotations

import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from twn_toolkit import create_app
from twn_toolkit.activity import ActivityStore
from twn_toolkit.auth import AuthStore
from twn_toolkit.dashboard_layout import DashboardLayoutStore
from twn_toolkit.live_tools import LiveToolStore
from twn_toolkit.server_settings import ServerSettingsStore
from twn_toolkit.version import RELEASE_NOTES


class HomePageTests(unittest.TestCase):
    def test_static_asset_version_changes_without_a_service_restart(self) -> None:
        with (
            tempfile.TemporaryDirectory() as instance,
            tempfile.TemporaryDirectory() as static,
        ):
            static_root = Path(static)
            probe = static_root / "probe.css"
            probe.write_text("body { color: black; }", encoding="utf-8")
            app = create_app(instance_path=instance)
            app.testing = True
            app.static_folder = str(static_root)
            app.config["ASSET_REVISION_CHECK_INTERVAL_SECONDS"] = 0
            client = app.test_client()

            first = client.get("/").data.decode()
            first_version = re.search(r"styles\.css\?v=([^\"&]+)", first).group(1)
            probe.write_text("body { color: chartreuse; }", encoding="utf-8")
            second = client.get("/").data.decode()
            second_version = re.search(r"styles\.css\?v=([^\"&]+)", second).group(1)

        self.assertNotEqual(first_version, second_version)

    def test_readme_wordmark_is_the_single_horizontal_twn_identity(self) -> None:
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        logo_path = (
            root
            / "twn_toolkit"
            / "static"
            / "brand"
            / "twn-toolkit-wordmark.svg"
        )
        logo = logo_path.read_text(encoding="utf-8")
        document = ET.fromstring(logo)
        namespace = {"svg": "http://www.w3.org/2000/svg"}
        text = [element.text for element in document.findall(".//svg:text", namespace)]

        self.assertIn("twn_toolkit/static/brand/twn-toolkit-wordmark.svg", readme)
        self.assertEqual(text, [">_TWN:~$", "toolkit"])
        self.assertEqual(document.attrib["viewBox"], "0 0 1120 240")
        self.assertNotIn("gradient", logo.lower())
        self.assertNotIn("dragon", logo.lower())

    def sidebar_category_panel(self, html: str, label: str) -> str:
        marker = f'data-nav-label="{label}"'
        start = html.index(marker)
        end = html.find('data-nav-category="category-', start + len(marker))
        return html[start : end if end >= 0 else html.index('class="side-nav-help', start)]

    def assert_sidebar_category_active(self, html: str, label: str) -> None:
        marker = f'data-nav-label="{label}"'
        marker_index = html.index(marker)
        details_index = html.rfind("<details", 0, marker_index)
        details_tag = html[details_index : html.index(">", marker_index)]
        self.assertIn('data-nav-active="true"', details_tag)
        self.assertIn(" open", details_tag)

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
            ServerSettingsStore(instance).save(
                "0.0.0.0",
                ["10.0.0.0/8"],
                instance_name="branch-tools",
            )

            response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Operator workspace", response.data)
        self.assertIn(b"Ready when you are, admin", response.data)
        self.assertIn(b"Quick launch", response.data)
        self.assertIn(b'id="dashboard-tool-search-input"', response.data)
        self.assertIn(b"Everything looks clear", response.data)
        self.assertIn(b"Activity snapshot", response.data)
        self.assertIn(b"All activity metrics", response.data)
        self.assertIn(b"Recent activity", response.data)
        self.assertIn(b"Favorites", response.data)
        self.assertNotIn(b"Team activity", response.data)
        self.assertIn(b"DNS", response.data)
        self.assertIn(b"Speed tests", response.data)
        self.assertIn(b"Syslog", response.data)
        self.assertIn(b"v0.22.1", response.data)
        self.assertIn(b'href="/help"', response.data)
        self.assertIn(b"Help &amp; release notes", response.data)
        self.assertIn(
            b'<small class="side-nav-instance">branch-tools</small>',
            response.data,
        )
        self.assertIn(b'<header class="topbar with-sidebar">', response.data)
        self.assertIn(b'id="side-nav-search-input"', response.data)
        self.assertLess(
            response.data.index(b'id="side-nav-search-input"'),
            response.data.index(b'side-nav-home'),
        )
        topnav = response.data.split(b'<nav class="topnav">', 1)[1].split(b"</nav>", 1)[0]
        self.assertNotIn(b"Settings", topnav)
        self.assertIn(b'aria-label="Appearance settings"', topnav)
        self.assertIn(b"appearance-toggle-label", topnav)
        self.assertIn(b'data-appearance-value="tokyo-night"', topnav)
        self.assertIn(b'data-appearance-value="focus"', topnav)
        workspace_choices = topnav.split(b"<legend>Workspace</legend>", 1)[1].split(
            b"</fieldset>", 1
        )[0]
        self.assertIn(b'data-appearance-value="tiled"', workspace_choices)
        self.assertNotIn(b'data-appearance-value="compact"', workspace_choices)
        self.assertIn(b"Packet Replay", response.data)
        self.assertIn(b"FortiGate", response.data)
        self.assertIn(b"Certificate Automation", response.data)
        self.assertNotIn("Certificate Automation · Beta".encode(), response.data)
        self.assertNotIn(b"Find Wireless Client History", response.data)
        self.assertNotIn(b"Re-order Managed FortiSwitches", response.data)

        sidebar_script = client.get("/static/sidebar.js")
        self.assertEqual(sidebar_script.status_code, 200)
        self.assertIn(b'link.closest(".side-nav-favorites")', sidebar_script.data)
        self.assertIn(b"openCategory", sidebar_script.data)
        self.assertIn(b"openSubgroup", sidebar_script.data)
        self.assertIn(b"setSidebarWidth", sidebar_script.data)
        self.assertIn(b'scroll.classList.toggle("searching"', sidebar_script.data)
        self.assertIn(b"renderDashboardSearch", sidebar_script.data)
        sidebar_script.close()

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
        self.assertIn(b"Using TWN Toolkit", response.data)
        self.assertIn(b"Profiles, secrets, and configuration backups", response.data)
        self.assertIn(b"Packet Replay", response.data)
        self.assertIn(b"Automations, schedules, conditions, and actions", response.data)
        self.assertIn(b"Home FortiGate = gate.example.com | 8443", response.data)
        self.assertIn(b"Syslog notification action", response.data)
        self.assertIn(b"./twn recover", response.data)
        self.assertIn(b"./twn fix-permissions", response.data)
        self.assertIn(b"./twn service install", response.data)
        self.assertIn(b"--network-capabilities", response.data)
        self.assertIn(b"Service uninstall removes only", response.data)
        self.assertIn(b'id="dhcp-discover"', response.data)
        self.assertIn(b"sends exactly one broadcast Discover", response.data)
        self.assertIn(b"never sends a Request", response.data)
        self.assertIn(b"ChmodBPF", response.data)
        self.assertIn(b"updater metadata ownership", response.data)
        self.assertIn(b"Dashboard and activity", response.data)
        self.assertIn(b"Operators can use every tool granted", response.data)
        self.assertIn(b"audit trail is role-neutral", response.data)
        self.assertIn(b"saved-profile and credential lifecycle", response.data)
        self.assertIn(b"rather than submitted targets, commands, payloads", response.data)
        self.assertIn(b"Release notes", response.data)
        self.assertIn(b"Updates &amp; Recovery", response.data)
        self.assertIn(b"./twn upgrade", response.data)
        self.assertIn(b"never runs older code against post-upgrade data", response.data)
        self.assertIn(
            b"updater first validates the replacement process set and finalizes",
            response.data,
        )
        self.assertIn(b"exactly one toolkit-start automation event", response.data)
        self.assertIn(b"v0.19.3", response.data)
        self.assertIn(
            b"Reliable protected macOS networking",
            response.data,
        )
        self.assertIn(
            b"Toolkit timezone and localized notifications",
            response.data,
        )
        self.assertIn(
            b"Production-scale diagnostics performance",
            response.data,
        )
        self.assertIn(
            b"Fast and resilient system diagnostics",
            response.data,
        )
        self.assertIn(
            b"Automation fallback routing and runtime diagnostics",
            response.data,
        )
        self.assertIn(b"Safe service-managed upgrade finalization", response.data)
        self.assertIn(
            b"Reliable service-managed upgrades",
            response.data,
        )
        self.assertIn(
            b"Startup announcements and system identity",
            response.data,
        )
        self.assertIn(
            b"Boot-managed service and macOS network-tool parity",
            response.data,
        )
        self.assertIn(
            b"Reliable automation cadence and Datastore packet replay",
            response.data,
        )
        self.assertIn(
            b"Multicast diagnostics and durable automation orchestration",
            response.data,
        )
        self.assertIn(
            b"iPerf3 diagnostics and supervised listeners",
            response.data,
        )
        self.assertIn(
            b"Ordered Favorites and DNS performance testing",
            response.data,
        )
        self.assertIn(
            b"Unified Multi-SSH workflow and compact host import",
            response.data,
        )
        self.assertIn(
            b"Variable-aware Multi-SSH Commandlets and fleet automation",
            response.data,
        )
        self.assertIn(b"Faster macOS CI and SMTP hostname handling", response.data)
        self.assertIn(b"Safe CLI recovery for orphaned servers", response.data)
        self.assertIn(b"Guided ACME certificate automation", response.data)
        self.assertIn(b"Reliable automation, packet capture", response.data)
        self.assertIn(b"v0.11.1", response.data)
        self.assertIn(b"Persistent live monitoring", response.data)
        self.assertIn(b"Certificate automation beta", response.data)
        self.assertIn(b"Certificate Automation:", response.data)
        self.assertIn(b"Microsoft AD CS workflow remains in Beta", response.data)
        self.assertIn(b"In-app upgrades, recovery points", response.data)
        self.assertIn(b"Login origin compatibility hotfix", response.data)
        self.assertIn(b"SNMP interface monitoring, audit completeness", response.data)
        self.assertIn(b"Managed service reliability hotfix", response.data)
        self.assertIn(b"Local services, transfer workflows, and operational hardening", response.data)
        self.assertIn(b"v0.8.0", response.data)
        self.assertEqual(
            response.data.count(b'class="help-topic release-note"'),
            len(RELEASE_NOTES),
        )
        self.assertIn(b'data-release-archive', response.data)
        self.assertIn(b"Older releases", response.data)
        self.assertIn(f"{len(RELEASE_NOTES) - 2} more versions".encode(), response.data)
        self.assertIn(b"data-help-search-status", response.data)
        self.assertNotIn(b'class="help-topic release-note" open', response.data)
        self.assertIn(b"Use at your own risk", response.data)

    def test_sidebar_groups_casework_local_tools_and_automation_as_operations(self) -> None:
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

        operations = self.sidebar_category_panel(response.data.decode(), "Operations").encode()
        self.assertLess(operations.index(b">Investigations</span>"), operations.index(b">Local Tools</strong>"))
        self.assertLess(operations.index(b">Local Tools</strong>"), operations.index(b">Automation</strong>"))
        administration = self.sidebar_category_panel(response.data.decode(), "Administration").encode()
        self.assertLess(
            administration.index(b">System Settings</span>"),
            administration.index(b">System Diagnostics</span>"),
        )
        self.assertLess(
            administration.index(b">System Diagnostics</span>"),
            administration.index(b">Updates &amp; Recovery</span>"),
        )

    def test_sidebar_places_investigations_inside_operations(self) -> None:
        with tempfile.TemporaryDirectory() as instance:
            app = create_app(instance_path=instance)
            app.testing = True
            client = app.test_client()

            page = client.get("/investigations").data.decode()

        operations = self.sidebar_category_panel(page, "Operations")
        self.assertRegex(operations, r'class="side-nav-tool-link\s+active"\s+href="/investigations"')
        self.assertEqual(operations.count(">Investigations</span>"), 1)
        self.assertIn("Add Investigations to favorites", operations)

    def test_profile_backup_moves_from_settings_to_updates_and_recovery(self) -> None:
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

            settings = client.get("/settings")
            updates = client.get("/settings/updates")
            backup = client.get("/settings/backup")

        self.assertNotIn(b">Configuration backup</h2>", settings.data)
        self.assertIn(b"><span>Configuration backups</span></a>", updates.data)
        self.assertIn(b"Create a configuration backup", backup.data)
        self.assertIn(
            b'aria-current="page"><span>Configuration backups</span></a>',
            backup.data,
        )
        self.assert_sidebar_category_active(backup.data.decode(), "Administration")

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

        self.assert_sidebar_category_active(fortigate, "Fortinet Tools")
        self.assertRegex(fortigate, r'class="side-nav-tool-link\s+active"\s+href="/fortigate"')
        self.assert_sidebar_category_active(fortiauthenticator, "Fortinet Tools")
        self.assertRegex(
            fortiauthenticator,
            r'class="side-nav-tool-link\s+active"\s+href="/fortiauthenticator"',
        )
        self.assert_sidebar_category_active(settings, "Administration")
        self.assertRegex(settings, r'class="side-nav-tool-link\s+active"\s+href="/settings"')
        self.assertNotIn('/favorites/tools/admin.settings', settings)

    def test_network_sidebar_reserves_icons_for_categories_not_leaf_tools(self) -> None:
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

            page = client.get("/tools/ping").data.decode()

        self.assert_sidebar_category_active(page, "Network Tools")
        self.assertIn("Addressing &amp; Reachability", page)
        self.assertNotIn("Multi-Host Tools", page)
        self.assertIn("Services &amp; Protocols", page)
        self.assertIn("Traffic &amp; Interfaces", page)
        self.assertIn('<span class="side-nav-icon" aria-hidden="true">⌁</span>', page)
        self.assertIn('<span class="side-nav-section-accent" aria-hidden="true">◎</span>', page)
        self.assertNotIn('<span class="side-nav-icon" aria-hidden="true">•</span>', page)
        ping_link = page.split('href="/tools/ping"', 1)[1].split("</a>", 1)[0]
        self.assertIn(">Ping</span>", ping_link)
        self.assertNotIn("side-nav-icon", ping_link)

    def test_sidebar_keeps_icons_for_direct_group_links_but_not_favorites(self) -> None:
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
            client.post("/favorites/tools/tools.ping")

            page = client.get("/investigations").data.decode()

        investigation = page.split('href="/investigations"', 1)[1].split(
            "</a>", 1
        )[0]
        self.assertIn("side-nav-icon", investigation)
        favorite = page.split('data-favorite-id="tools.ping"', 1)[1].split(
            "</li>", 1
        )[0]
        self.assertIn(">Ping</span>", favorite)
        self.assertNotIn("side-nav-icon", favorite)

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

    def test_user_can_reorder_favorites_for_sidebar_and_quick_launch(self) -> None:
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
            for tool_id in (
                "tools.ping",
                "tools.dns_response",
                "tools.packet_capture",
            ):
                client.post(f"/favorites/tools/{tool_id}", data={"next": "/"})

            response = client.post(
                "/favorites/order",
                data={
                    "order": (
                        "tools.packet_capture,tools.ping,tools.dns_response"
                    ),
                    "next": "/",
                },
            )
            user = AuthStore(instance).get_user("admin")
            page = client.get("/")
            invalid = client.post(
                "/favorites/order",
                data={"order": "tools.ping", "next": "/"},
            )
            autosaved = client.post(
                "/favorites/order",
                data={
                    "order": (
                        "tools.packet_capture,tools.ping,tools.dns_response"
                    ),
                    "next": "/",
                },
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            script = client.get("/static/favorites-order.js")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            user["favorite_tools"],
            ["tools.packet_capture", "tools.ping", "tools.dns_response"],
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(autosaved.status_code, 204)
        self.assertNotIn(b">Reorder</button>", page.data)
        self.assertNotIn(b"data-favorites-editor", page.data)
        self.assertIn(b"data-favorites-reorder", page.data)
        self.assertIn(b'data-favorites-order-form', page.data)
        favorites_html = page.data.split(b"data-favorites-list", 1)[1].split(
            b"</ul>", 1
        )[0]
        self.assertIn(b'draggable="true"', favorites_html)
        self.assertIn(
            b"Reorder Packet Capture; use Up and Down arrow keys",
            favorites_html,
        )
        self.assertLess(
            favorites_html.index(b"Packet Capture"),
            favorites_html.index(b">Ping</span>"),
        )
        self.assertLess(
            favorites_html.index(b">Ping</span>"),
            favorites_html.index(b"DNS Tester"),
        )
        quick_launch_html = page.data.split(b"workspace-quick-grid", 1)[1].split(
            b"</div>", 1
        )[0]
        self.assertLess(
            quick_launch_html.index(b"Packet Capture"),
            quick_launch_html.index(b">Ping<"),
        )
        self.assertEqual(script.status_code, 200)
        self.assertIn(b"ArrowDown", script.data)
        self.assertIn(b"fetch(form.action", script.data)
        self.assertIn(b"DOMParser", script.data)
        self.assertNotIn(b"setEditing", script.data)

    def test_dashboard_surfaces_live_tool_attention(self) -> None:
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
            user = AuthStore(instance).get_user("admin")
            live_store = LiveToolStore(instance)
            live_session = live_store.create_ping_session(
                user_id=user["id"],
                username=user["username"],
                title="Branch reachability",
                targets=[{"host": "192.0.2.1", "label": "Branch"}],
                interval=2,
                timeout=1,
            )
            live_store.record_error(
                live_session["id"],
                revision=live_session["revision"],
                message="The branch stopped responding.",
            )

            page = client.get("/")

        self.assertIn(b"1 item needs attention", page.data)
        self.assertIn(b"1 active", page.data)
        self.assertIn(b"1 stopped with an error", page.data)
        self.assertIn(b"data-open-live-tools", page.data)

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
        self.assertIn(b"<strong>5</strong>", page.data)
        self.assertIn(b"<span>sent</span>", page.data)
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
        self.assertIn(b"Customize activity", page.data)
        self.assertIn(b"Save layout", page.data)
        self.assertIn(b"Hidden metrics", page.data)
        self.assertIn(
            f'data-widget-id="{metric_ids[0]}" data-widget-hidden="true" hidden'.encode(),
            page.data,
        )
        self.assertNotIn(
            f'data-widget-id="{metric_ids[0]}"'.encode(), operator_page.data
        )
        self.assertNotIn(b"Customize activity", operator_page.data)
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
        self.assertNotIn(b"Team activity", after_all.data)
        self.assertNotIn(b'class="scoreboard-entry"', after_all.data)

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

        self.assertIn(b"Latest 8 of 10", page.data)
        self.assertIn(b"events from lifetime", page.data)
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
        self.assertIn(
            b'name="scoreboard_rank" value="ping.probes_sent"', page.data
        )
        self.assertIn(b"Your first four visible metrics for last hour", page.data)

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
