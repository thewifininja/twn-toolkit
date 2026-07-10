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


class ToolRegistryTests(unittest.TestCase):
    def test_registry_builds_existing_lookup_maps(self) -> None:
        self.assertIn("tools.packet_replay", TOOL_BY_ID)
        self.assertEqual(TASK_TOOL_IDS["rename-aps"], "fortigate.rename_aps")
        self.assertEqual(
            tool_id_for_endpoint("tools.packet_replay"),
            "tools.packet_replay",
        )
        self.assertEqual(
            tool_id_for_endpoint("task_form", {"task_id": "export-switches"}),
            "fortigate.export_switches",
        )
        self.assertEqual(
            REGISTRY.tool_id_for_endpoint("fortiap_client_history"),
            "fortigate.wireless_client_history",
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
            "login",
            "logout",
            "reset_activity_metric",
            "reset_activity_scoreboard",
            "reset_activity_user_score",
            "settings",
            "setup",
            "static",
            "tools.index",
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
