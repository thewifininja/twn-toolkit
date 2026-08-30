from __future__ import annotations

def backup_items(instance_path: str):
    from twn_toolkit.auth import AuthStore, load_or_create_secret_key
    from twn_toolkit.certificate_automation import CertificateAutomationStore
    from twn_toolkit.configuration_backup_stores import (
        AccessProfilesBackupStore,
        CertificateAutomationProfilesBackupStore,
        RemoteConnectionBackupStore,
        SMTPSettingsBackupStore,
        TimeSettingsBackupStore,
    )
    from twn_toolkit.dashboard_layout import (
        DashboardLayoutBackupStore,
        DashboardLayoutStore,
    )
    from twn_toolkit.remote_connections import RemoteConnectionStore
    from twn_toolkit.smtp_tools import SMTPSettingsStore
    from twn_toolkit.time_settings import TimeSettingsStore

    secret_key = load_or_create_secret_key(instance_path)
    auth_store = AuthStore(instance_path)
    return [
        {
            "id": "dashboard_layout",
            "label": "Dashboard layout",
            "description": "Global metric widget order and visibility. No activity history is included.",
            "category": "Administration",
            "store": DashboardLayoutBackupStore(DashboardLayoutStore(instance_path)),
            "sensitive": False,
        },
        {
            "id": "remote_connection_library",
            "label": "Remote Terminal libraries",
            "description": "User-owned saved folders, SSH and Telnet hosts, and credentials. Active sessions and scrollback are excluded.",
            "category": "Remote access",
            "store": RemoteConnectionBackupStore(
                RemoteConnectionStore(instance_path, secret_key), auth_store
            ),
            "sensitive": True,
        },
        {
            "id": "certificate_automation_profiles",
            "label": "Certificate Automation profiles",
            "description": "PKI credentials, servers, templates, and managed definitions. Issued certificates, private keys, and request history are excluded.",
            "category": "Network tools",
            "store": CertificateAutomationProfilesBackupStore(
                CertificateAutomationStore(instance_path, secret_key)
            ),
            "sensitive": True,
            "supports_replace": False,
            "atomic_last": True,
        },
        {
            "id": "access_profiles",
            "label": "Access profiles",
            "description": "Custom tool-permission definitions. Users, passwords, and profile assignments are excluded.",
            "category": "Administration",
            "store": AccessProfilesBackupStore(auth_store),
            "sensitive": False,
        },
        {
            "id": "smtp_settings",
            "label": "SMTP delivery settings",
            "description": "Mail server, sender, TLS configuration, and saved SMTP credentials.",
            "category": "Administration",
            "store": SMTPSettingsBackupStore(
                SMTPSettingsStore(instance_path, secret_key)
            ),
            "sensitive": True,
        },
        {
            "id": "time_settings",
            "label": "Toolkit timezone",
            "description": "The explicit IANA timezone used for toolkit displays and scheduling context.",
            "category": "Administration",
            "store": TimeSettingsBackupStore(TimeSettingsStore(instance_path)),
            "sensitive": False,
        },
    ]


def register_tools(registry) -> None:
    from twn_toolkit.tool_catalog import ToolLink

    registry.add_tool(
        ToolLink(
            "admin.settings",
            "System Settings",
            "Configure server access, timezone, email delivery, operational limits, users, and access profiles.",
            "settings",
            "administration",
            "Administration",
            admin_only=True,
            grantable=False,
            nav_icon="⚙",
        )
    )
    registry.add_tool(
        ToolLink(
            "admin.diagnostics", "System Diagnostics",
            "Review process health, storage, databases, dependencies, migrations, and audit history.",
            "diagnostics", "administration", "Administration",
            admin_only=True, grantable=False, nav_icon="♥",
        )
    )
    registry.add_tool(
        ToolLink(
            "admin.updates", "Updates & Recovery",
            "Manage configuration backups, verified releases, recovery points, upgrades, and restores.",
            "updates", "administration", "Administration",
            admin_only=True, grantable=False, nav_icon="↻",
        )
    )
    registry.map_endpoints(
        {
            "backup_settings": "admin.updates",
            "create_user": "admin.settings",
            "update_user_access": "admin.settings",
            "save_access_profile": "admin.settings",
            "duplicate_access_profile": "admin.settings",
            "delete_access_profile": "admin.settings",
            "delete_user": "admin.settings",
            "update_session_settings": "admin.settings",
            "update_server_settings": "admin.settings",
            "update_time_settings": "admin.settings",
            "apply_raspberry_pi_networking": "admin.settings",
            "confirm_raspberry_pi_networking": "admin.settings",
            "rollback_raspberry_pi_networking": "admin.settings",
            "disable_raspberry_pi_networking": "admin.settings",
            "delete_raspberry_pi_network_profile": "admin.settings",
            "toggle_raspberry_pi_network_profile": "admin.settings",
            "scan_raspberry_pi_wifi": "admin.settings",
            "update_smtp_settings": "admin.settings",
            "test_smtp_settings": "admin.settings",
            "update_automation_retention": "admin.settings",
            "prune_automation_history": "admin.settings",
            "optimize_automation_database": "admin.settings",
            "export_profile_backup": "admin.updates",
            "inspect_configuration_backup": "admin.updates",
            "import_profile_backup": "admin.updates",
            "update_operational_settings": "admin.settings",
            "diagnostics": "admin.diagnostics",
            "cleanup_orphan_artifacts": "admin.diagnostics",
            "updates": "admin.updates",
            "update_status": "admin.updates",
            "install_update": "admin.updates",
            "upload_update_bundle": "admin.updates",
            "create_recovery_point": "admin.updates",
            "rollback_update": "admin.updates",
        }
    )
