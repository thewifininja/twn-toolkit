from __future__ import annotations

from typing import Any

from twn_toolkit.profiles import ProfileStore
from twn_toolkit.tool_catalog import ToolLink, ToolRegistry


def backup_items(instance_path: str) -> list[dict[str, Any]]:
    return [
        {
            "id": "fortigate_profiles",
            "label": "FortiGate profiles",
            "description": "Saved FortiGate URLs, default VDOMs, TLS choices, and API keys.",
            "store": ProfileStore(instance_path),
            "sensitive": True,
        },
    ]


def register_tools(registry: ToolRegistry) -> None:
    registry.add_tools(
        [
            ToolLink(
                "fortigate.home",
                "FortiGate",
                "Profiles, FortiAP/FortiSwitch workflows, inventory exports, and bulk operations.",
                "fortigate_home",
                "fortigate",
                "Fortinet Workflows",
            ),
            ToolLink(
                "fortigate.wireless_client_history",
                "Find Wireless Client History",
                "Search local wireless-client logs and show the AP path for a client MAC.",
                "fortiap_client_history",
                "fortigate",
                "FortiAP Tasks",
                show_on_home=False,
            ),
            ToolLink(
                "fortigate.rename_aps",
                "Bulk Rename APs",
                "Rename managed wireless APs in the browser or from a CSV import.",
                "task_form",
                "fortigate",
                "FortiAP Tasks",
                endpoint_values={"task_id": "rename-aps"},
                risk="advanced",
                show_on_home=False,
            ),
            ToolLink(
                "fortigate.export_aps",
                "Export AP Data",
                "Download managed AP inventory data as CSV.",
                "task_form",
                "fortigate",
                "FortiAP Tasks",
                endpoint_values={"task_id": "export-aps"},
                show_on_home=False,
            ),
            ToolLink(
                "fortigate.export_wireless_clients",
                "Export Wireless Clients",
                "Download currently detected wireless client data as CSV.",
                "task_form",
                "fortigate",
                "FortiAP Tasks",
                endpoint_values={"task_id": "export-wireless-clients"},
                show_on_home=False,
            ),
            ToolLink(
                "fortigate.switch_order",
                "Re-order Managed FortiSwitches",
                "Drag managed FortiSwitches into the desired GUI order or alphabetize them.",
                "switch_order",
                "fortigate",
                "FortiSwitch Tasks",
                show_on_home=False,
            ),
            ToolLink(
                "fortigate.rename_switches",
                "Bulk Rename FortiSwitches",
                "Rename managed FortiSwitches in the browser or from a CSV import.",
                "task_form",
                "fortigate",
                "FortiSwitch Tasks",
                endpoint_values={"task_id": "rename-switches"},
                risk="advanced",
                show_on_home=False,
            ),
            ToolLink(
                "fortigate.export_switches",
                "Export FortiSwitch Data",
                "Download managed FortiSwitch inventory data as CSV.",
                "task_form",
                "fortigate",
                "FortiSwitch Tasks",
                endpoint_values={"task_id": "export-switches"},
                show_on_home=False,
            ),
            ToolLink(
                "fortigate.export_fortiswitch_clients",
                "Export FortiSwitch Clients",
                "Download currently detected FortiSwitch client data as CSV.",
                "task_form",
                "fortigate",
                "FortiSwitch Tasks",
                endpoint_values={"task_id": "export-fortiswitch-clients"},
                show_on_home=False,
            ),
        ]
    )
    registry.map_endpoints(
        {
            "save_profile": "fortigate.home",
            "delete_profile": "fortigate.home",
            "test_profile": "fortigate.home",
            "fortiap_client_history": "fortigate.wireless_client_history",
            "switch_order": "fortigate.switch_order",
            "switch_order_objects": "fortigate.switch_order",
            "apply_switch_order": "fortigate.switch_order",
        }
    )
