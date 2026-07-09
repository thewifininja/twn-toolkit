from __future__ import annotations

from typing import Any

from twn_toolkit.profiles import FortiAuthenticatorProfileStore
from twn_toolkit.tool_catalog import ToolLink, ToolRegistry


def backup_items(instance_path: str) -> list[dict[str, Any]]:
    return [
        {
            "id": "fortiauthenticator_profiles",
            "label": "FortiAuthenticator profiles",
            "description": "Saved FortiAuthenticator URLs, users, TLS choices, timeouts, and passwords.",
            "store": FortiAuthenticatorProfileStore(instance_path),
            "sensitive": True,
        },
    ]


def register_tools(registry: ToolRegistry) -> None:
    registry.add_tools(
        [
            ToolLink(
                "fortiauthenticator.home",
                "FortiAuthenticator",
                "Profiles and MAC device administration workflows.",
                "fortiauthenticator_home",
                "fortiauthenticator",
                "Fortinet Workflows",
            ),
            ToolLink(
                "fortiauthenticator.mac_devices",
                "Export MAC Devices",
                "Preview and export the complete paginated MAC device inventory.",
                "fortiauthenticator_mac_devices",
                "fortiauthenticator",
                "FortiAuthenticator Workflows",
                show_on_home=False,
            ),
            ToolLink(
                "fortiauthenticator.group_memberships",
                "Export Group Memberships",
                "Preview and export device-to-group membership data.",
                "fortiauthenticator_mac_group_memberships",
                "fortiauthenticator",
                "FortiAuthenticator Workflows",
                show_on_home=False,
            ),
            ToolLink(
                "fortiauthenticator.mac_cleanup",
                "MAC Device Cleanup",
                "Preview group removal or global device deletion.",
                "fortiauthenticator_mac_cleanup",
                "fortiauthenticator",
                "FortiAuthenticator Workflows",
                risk="high",
                show_on_home=False,
            ),
        ]
    )
    registry.map_endpoints(
        {
            "save_fortiauthenticator_profile": "fortiauthenticator.home",
            "delete_fortiauthenticator_profile": "fortiauthenticator.home",
            "test_fortiauthenticator_profile": "fortiauthenticator.home",
            "fortiauthenticator_mac_devices": "fortiauthenticator.mac_devices",
            "export_fortiauthenticator_mac_devices": "fortiauthenticator.mac_devices",
            "fortiauthenticator_mac_group_memberships": "fortiauthenticator.group_memberships",
            "export_fortiauthenticator_mac_group_memberships": "fortiauthenticator.group_memberships",
            "fortiauthenticator_mac_cleanup": "fortiauthenticator.mac_cleanup",
            "execute_fortiauthenticator_mac_cleanup": "fortiauthenticator.mac_cleanup",
        }
    )
