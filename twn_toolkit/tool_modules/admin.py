from __future__ import annotations

from twn_toolkit.tool_catalog import ToolLink, ToolRegistry


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
            "export_profile_backup": "admin.settings",
            "import_profile_backup": "admin.settings",
        }
    )
