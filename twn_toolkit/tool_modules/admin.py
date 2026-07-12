from __future__ import annotations

from twn_toolkit.tool_catalog import ToolLink, ToolRegistry


def backup_items(instance_path: str):
    from twn_toolkit.dashboard_layout import (
        DashboardLayoutBackupStore,
        DashboardLayoutStore,
    )

    return [
        {
            "id": "dashboard_layout",
            "label": "Dashboard layout",
            "description": "Global metric widget order and visibility. No activity history is included.",
            "store": DashboardLayoutBackupStore(DashboardLayoutStore(instance_path)),
            "sensitive": False,
        }
    ]


def register_tools(registry: ToolRegistry) -> None:
    registry.add_tool(
        ToolLink(
            "admin.settings",
            "Settings",
            "Manage users, password policy, server access, and profile backup/restore.",
            "settings",
            "administration",
            "Administration",
            admin_only=True,
            grantable=False,
        )
    )
    registry.map_endpoints(
        {
            "backup_settings": "admin.settings",
            "create_user": "admin.settings",
            "update_user_access": "admin.settings",
            "save_access_profile": "admin.settings",
            "delete_access_profile": "admin.settings",
            "delete_user": "admin.settings",
            "update_session_settings": "admin.settings",
            "update_server_settings": "admin.settings",
            "update_automation_retention": "admin.settings",
            "prune_automation_history": "admin.settings",
            "optimize_automation_database": "admin.settings",
            "export_profile_backup": "admin.settings",
            "import_profile_backup": "admin.settings",
        }
    )
