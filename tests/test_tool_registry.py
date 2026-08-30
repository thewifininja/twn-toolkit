from __future__ import annotations

import unittest

from twn_toolkit import create_app
from twn_toolkit.tool_catalog import (
    ENDPOINT_TOOL_IDS,
    REGISTRY,
    TASK_TOOL_IDS,
    TOOLS,
    TOOL_BY_ID,
    ToolLink,
    ToolRegistry,
    grouped_access_tools,
    tool_id_for_endpoint,
)
from twn_toolkit.investigation_policy import CAPTURE_POLICIES, CAPTURE_MODES
from twn_toolkit.investigation_reporting import REPORT_PRESENTATION_TOOL_IDS


class ToolRegistryTests(unittest.TestCase):
    def test_every_registered_tool_has_an_investigation_capture_policy(self) -> None:
        self.assertEqual(set(CAPTURE_POLICIES), set(TOOL_BY_ID))
        for tool_id, policy in CAPTURE_POLICIES.items():
            self.assertIn(policy.mode, CAPTURE_MODES, tool_id)
            self.assertTrue(policy.evidence, tool_id)
            self.assertTrue(policy.rationale, tool_id)

    def test_automatic_case_evidence_has_an_explicit_report_presentation(self) -> None:
        required = {
            tool_id
            for tool_id, policy in CAPTURE_POLICIES.items()
            if policy.mode in {"finite", "lifecycle", "hybrid", "action"}
        }
        self.assertEqual(required - REPORT_PRESENTATION_TOOL_IDS, set())

    def test_registry_builds_existing_lookup_maps(self) -> None:
        self.assertIn("tools.packet_replay", TOOL_BY_ID)
        self.assertIn("tools.packet_capture", TOOL_BY_ID)
        self.assertIn("tools.iperf3", TOOL_BY_ID)
        self.assertIn("tools.multicast", TOOL_BY_ID)
        self.assertIn("tools.wake_on_lan", TOOL_BY_ID)
        self.assertIn("investigations.workspace", TOOL_BY_ID)
        self.assertEqual(TOOL_BY_ID["tools.iperf3"].nav_group, "traffic")
        self.assertEqual(TOOL_BY_ID["tools.multicast"].nav_group, "traffic")
        self.assertEqual(TOOL_BY_ID["tools.wake_on_lan"].nav_group, "services")
        self.assertEqual(TASK_TOOL_IDS["rename-aps"], "fortigate.rename_aps")
        self.assertEqual(
            tool_id_for_endpoint("tools.packet_replay"),
            "tools.packet_replay",
        )
        self.assertEqual(
            tool_id_for_endpoint("tools.packet_capture_status"),
            "tools.packet_capture",
        )
        self.assertEqual(
            tool_id_for_endpoint("task_form", {"task_id": "export-switches"}),
            "fortigate.export_switches",
        )
        self.assertEqual(
            REGISTRY.tool_id_for_endpoint("fortiap_client_history"),
            "fortigate.wireless_client_history",
        )
        self.assertEqual(
            REGISTRY.tool_id_for_endpoint("investigation_report"),
            "investigations.workspace",
        )
        self.assertEqual(
            REGISTRY.tool_id_for_endpoint("download_investigation_package"),
            "investigations.workspace",
        )

    def test_registry_rejects_duplicate_tool_ids(self) -> None:
        registry = ToolRegistry([])
        tool = ToolLink(
            "example.tool",
            "Example",
            "Example tool.",
            "example.endpoint",
            "network",
            "Network Tools",
        )
        registry.add_tool(tool)
        with self.assertRaises(ValueError):
            registry.add_tool(tool)

    def test_registry_rejects_endpoint_mapping_to_unknown_tool(self) -> None:
        registry = ToolRegistry([])
        with self.assertRaises(ValueError):
            registry.map_endpoint("example.endpoint", "missing.tool")

    def test_registered_endpoint_mappings_point_to_real_tools(self) -> None:
        for endpoint, tool_id in ENDPOINT_TOOL_IDS.items():
            with self.subTest(endpoint=endpoint):
                self.assertIn(tool_id, TOOL_BY_ID)

    def test_task_tools_have_task_ids_and_unique_ids(self) -> None:
        ids = [tool.id for tool in TOOLS]
        self.assertEqual(len(ids), len(set(ids)))
        for tool in TOOLS:
            if tool.endpoint == "task_form":
                self.assertIn("task_id", tool.endpoint_values)
                self.assertEqual(TASK_TOOL_IDS[tool.endpoint_values["task_id"]], tool.id)

    def test_access_profile_groups_exclude_non_grantable_tools(self) -> None:
        access_tool_ids = {
            tool.id
            for _group, tools in grouped_access_tools()
            for tool in tools
        }
        self.assertIn("tools.packet_replay", access_tool_ids)
        self.assertIn("tools.packet_capture", access_tool_ids)
        self.assertIn("tools.multicast", access_tool_ids)
        self.assertNotIn("admin.settings", access_tool_ids)

    def test_logged_in_routes_are_mapped_or_intentionally_self_service(self) -> None:
        app = create_app()
        task_endpoints = {
            "task_form",
            "task_csv_template",
            "run_task",
            "task_objects",
            "rename_objects",
            "task_fields",
            "task_preview",
        }
        public_or_self_service = {
            "favicon",
            "health",
            "help_page",
            "index",
            "save_dashboard_layout",
            "reset_dashboard_layout",
            "login",
            "logout",
            "reset_activity_metric",
            "reset_activity_scoreboard",
            "reset_activity_user_score",
            "reorder_tool_favorites",
            "settings",
            "setup",
            "static",
            "tools.index",
            "tools.live_tool_sessions",
            "tools.rename_live_tool_session",
            "tools.stop_live_tool_session",
            "update_appearance",
            "update_theme",
            "change_user_password",
            "toggle_tool_favorite",
            "fortigate_home",
            "fortiauthenticator_home",
        }
        checked_endpoints = {
            rule.endpoint
            for rule in app.url_map.iter_rules()
            if not rule.endpoint.startswith("static")
        }
        unmapped = checked_endpoints - set(ENDPOINT_TOOL_IDS) - task_endpoints - public_or_self_service

        self.assertEqual(sorted(unmapped), [])


if __name__ == "__main__":
    unittest.main()
