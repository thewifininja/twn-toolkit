from __future__ import annotations

from twn_toolkit.tool_catalog import ToolLink, ToolRegistry


def backup_items(instance_path: str):
    from twn_toolkit.auth import load_or_create_secret_key
    from twn_toolkit.automation import AutomationBackupStore, AutomationStore

    store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
    return [
        {
            "id": "automation_definitions",
            "label": "Automation definitions",
            "description": "Conditions, trigger policies, SSH actions, and saved credentials. Runtime history is excluded.",
            "store": AutomationBackupStore(store),
            "sensitive": True,
        }
    ]


def register_tools(registry: ToolRegistry) -> None:
    registry.add_tool(
        ToolLink(
            "automation.home",
            "Automations",
            "Connect scheduled network conditions to trusted response actions.",
            "automations",
            "automation",
            "Automation",
            admin_only=True,
            risk="advanced",
            grantable=False,
            nav_icon="⚙",
        )
    )
    registry.map_endpoints(
        {
            "automations": "automation.home",
            "save_automation": "automation.home",
            "save_automation_condition": "automation.home",
            "save_automation_action": "automation.home",
            "test_condition_definition": "automation.home",
            "delete_automation_condition": "automation.home",
            "delete_automation_action": "automation.home",
            "toggle_automation": "automation.home",
            "run_automation_now": "automation.home",
            "test_automation_condition": "automation.home",
            "delete_automation": "automation.home",
            "clear_automation_runs": "automation.home",
            "delete_automation_run": "automation.home",
            "download_automation_run": "automation.home",
        }
    )
