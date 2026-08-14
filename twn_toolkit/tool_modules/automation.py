from __future__ import annotations

def backup_items(instance_path: str):
    from twn_toolkit.auth import load_or_create_secret_key
    from twn_toolkit.automation import AutomationBackupStore, AutomationStore

    store = AutomationStore(instance_path, load_or_create_secret_key(instance_path))
    return [
        {
            "id": "automation_definitions",
            "label": "Automation definitions",
            "description": "Schedules, conditions, actions, and saved credentials. Runtime history is excluded.",
            "category": "Automation",
            "store": AutomationBackupStore(store),
            "sensitive": True,
            "supports_replace": False,
        }
    ]


def register_tools(registry) -> None:
    from twn_toolkit.tool_catalog import ToolLink

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
    registry.add_tool(
        ToolLink(
            "automation.schedules",
            "Schedules",
            "Create reusable calendars for scheduled automations.",
            "automation_schedules",
            "automation",
            "Automation",
            admin_only=True,
            risk="advanced",
            grantable=False,
            nav_icon="▦",
        )
    )
    registry.add_tool(
        ToolLink(
            "automation.conditions",
            "Conditions",
            "Create and test reusable observations for automations.",
            "automation_conditions",
            "automation",
            "Automation",
            admin_only=True,
            risk="advanced",
            grantable=False,
            nav_icon="IF",
        )
    )
    registry.add_tool(
        ToolLink(
            "automation.actions",
            "Actions",
            "Create reusable responses for automation pipelines.",
            "automation_actions",
            "automation",
            "Automation",
            admin_only=True,
            risk="advanced",
            grantable=False,
            nav_icon="▶",
        )
    )
    registry.map_endpoints(
        {
            "automations": "automation.home",
            "save_automation": "automation.home",
            "duplicate_automation": "automation.home",
            "automation_conditions": "automation.conditions",
            "save_automation_condition": "automation.conditions",
            "duplicate_automation_condition": "automation.conditions",
            "test_condition_definition": "automation.conditions",
            "delete_automation_condition": "automation.conditions",
            "automation_schedules": "automation.schedules",
            "save_automation_schedule": "automation.schedules",
            "duplicate_automation_schedule": "automation.schedules",
            "test_schedule_definition": "automation.schedules",
            "delete_automation_schedule": "automation.schedules",
            "automation_actions": "automation.actions",
            "save_automation_action": "automation.actions",
            "duplicate_automation_action": "automation.actions",
            "delete_automation_action": "automation.actions",
            "toggle_automation": "automation.home",
            "run_automation_now": "automation.home",
            "test_automation_condition": "automation.home",
            "delete_automation": "automation.home",
            "retry_failed_automation_jobs": "automation.home",
            "clear_automation_runs": "automation.home",
            "delete_automation_run": "automation.home",
            "download_automation_run": "automation.home",
            "add_automation_run_to_case": "automation.home",
        }
    )
