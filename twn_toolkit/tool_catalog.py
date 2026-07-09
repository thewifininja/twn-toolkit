from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolLink:
    id: str
    label: str
    description: str
    endpoint: str
    category: str
    category_label: str
    admin_only: bool = False
    endpoint_values: dict[str, Any] = field(default_factory=dict)
    risk: str = "standard"
    show_on_home: bool = True
    grantable: bool = True


TOOL_CATEGORIES = [
    {
        "id": "fortigate",
        "label": "FortiGate / FortiAP / FortiSwitch",
        "description": "Profiles, inventory exports, bulk renaming, switch ordering, and wireless client history.",
        "endpoint": "fortigate_home",
    },
    {
        "id": "fortiauthenticator",
        "label": "FortiAuthenticator",
        "description": "MAC device exports, group membership review, and cleanup workflows.",
        "endpoint": "fortiauthenticator_home",
    },
    {
        "id": "network",
        "label": "Network Tools",
        "description": "Vendor-neutral diagnostics that run from the toolkit host or your browser.",
        "endpoint": "tools.index",
    },
    {
        "id": "administration",
        "label": "Administration",
        "description": "User settings, access controls, profile backup, and server listener settings.",
        "endpoint": "settings",
    },
]


TOOLS = [
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
    ToolLink(
        "tools.whats_my_ip",
        "What’s My IP?",
        "See the client address used to connect to this toolkit server.",
        "tools.whats_my_ip",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.subnet_excluder",
        "Subnet Excluder",
        "Subtract CIDR networks from one or more parent networks.",
        "tools.subnet_excluder",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.ping",
        "Multi-Host Ping",
        "Troubleshoot reachability, latency, and packet loss across multiple hosts.",
        "tools.ping_tool",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.multi_ssh",
        "Multi-SSH",
        "Run the same command sequence across multiple SSH hosts.",
        "tools.multi_ssh",
        "network",
        "Network Tools",
        risk="advanced",
    ),
    ToolLink(
        "tools.dns_response",
        "DNS Lookup Tester",
        "Compare DNS answers and lookup latency across multiple resolvers.",
        "tools.dns_response",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.radius_test",
        "RADIUS Authentication Test",
        "Compare PAP, CHAP, PEAP/MSCHAPv2, or EAP-TLS authentication across RADIUS servers.",
        "tools.radius_test",
        "network",
        "Network Tools",
        risk="advanced",
    ),
    ToolLink(
        "tools.speed_test",
        "Wi-Fi / LAN Speed Test",
        "Measure browser-to-toolkit latency, jitter, download, and upload on the local network.",
        "tools.speed_test",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.certificate_inspector",
        "Certificate Chain Inspector",
        "Inspect the exact TLS chain a web server presents and validate trust and hostnames.",
        "tools.certificate_inspector",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.snmp_test",
        "SNMP Tester",
        "Validate SNMPv2c and SNMPv3 access with reusable devices, credentials, and OID collections.",
        "tools.snmp_test",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.port_scanner",
        "TCP Port Scanner",
        "Check selected TCP ports across multiple authorized hosts.",
        "tools.port_scanner",
        "network",
        "Network Tools",
        risk="advanced",
    ),
    ToolLink(
        "tools.ntp_test",
        "NTP Tester",
        "Measure clock offset, response delay, jitter, and synchronization health.",
        "tools.ntp_test",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.dhcp_discover",
        "DHCP Discover",
        "Send a Discover and inspect Offers without requesting a lease.",
        "tools.dhcp_discover",
        "network",
        "Network Tools",
        risk="advanced",
    ),
    ToolLink(
        "tools.packet_replay",
        "Packet Replay",
        "Preview, lightly modify, and transmit a bounded raw Ethernet frame.",
        "tools.packet_replay",
        "network",
        "Network Tools",
        admin_only=True,
        risk="high",
    ),
    ToolLink(
        "tools.path_mtu",
        "Path MTU Tester",
        "Find the largest unfragmented packet that reaches a destination.",
        "tools.path_mtu",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.api_request",
        "Webhook / API Tester",
        "Send a bounded HTTP request and inspect status, timing, headers, and body.",
        "tools.api_request",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.syslog_receiver",
        "Syslog Tools",
        "Generate test messages or listen briefly for UDP and TCP syslog traffic.",
        "tools.syslog_receiver",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "tools.traceroute",
        "Traceroute",
        "Trace up to 10 destinations with live graphical hops and text output.",
        "tools.traceroute",
        "network",
        "Network Tools",
    ),
    ToolLink(
        "admin.settings",
        "Settings",
        "Manage users, password policy, server access, and profile backup/restore.",
        "settings",
        "administration",
        "Administration",
        admin_only=True,
        grantable=False,
    ),
]


TOOL_BY_ID = {tool.id: tool for tool in TOOLS}


TASK_TOOL_IDS = {
    str(tool.endpoint_values.get("task_id")): tool.id
    for tool in TOOLS
    if tool.endpoint == "task_form" and tool.endpoint_values.get("task_id")
}

ENDPOINT_TOOL_IDS = {
    "save_profile": "fortigate.home",
    "delete_profile": "fortigate.home",
    "test_profile": "fortigate.home",
    "fortiap_client_history": "fortigate.wireless_client_history",
    "switch_order": "fortigate.switch_order",
    "switch_order_objects": "fortigate.switch_order",
    "apply_switch_order": "fortigate.switch_order",
    "save_fortiauthenticator_profile": "fortiauthenticator.home",
    "delete_fortiauthenticator_profile": "fortiauthenticator.home",
    "test_fortiauthenticator_profile": "fortiauthenticator.home",
    "fortiauthenticator_mac_devices": "fortiauthenticator.mac_devices",
    "export_fortiauthenticator_mac_devices": "fortiauthenticator.mac_devices",
    "fortiauthenticator_mac_group_memberships": "fortiauthenticator.group_memberships",
    "export_fortiauthenticator_mac_group_memberships": "fortiauthenticator.group_memberships",
    "fortiauthenticator_mac_cleanup": "fortiauthenticator.mac_cleanup",
    "execute_fortiauthenticator_mac_cleanup": "fortiauthenticator.mac_cleanup",
    "backup_settings": "admin.settings",
    "create_user": "admin.settings",
    "delete_user": "admin.settings",
    "update_session_settings": "admin.settings",
    "update_server_settings": "admin.settings",
    "export_profile_backup": "admin.settings",
    "import_profile_backup": "admin.settings",
    "tools.dhcp_discover": "tools.dhcp_discover",
    "tools.packet_replay": "tools.packet_replay",
    "tools.path_mtu": "tools.path_mtu",
    "tools.api_request": "tools.api_request",
    "tools.syslog_receiver": "tools.syslog_receiver",
    "tools.whats_my_ip": "tools.whats_my_ip",
    "tools.ntp_test": "tools.ntp_test",
    "tools.save_ntp_profile": "tools.ntp_test",
    "tools.delete_ntp_profile": "tools.ntp_test",
    "tools.traceroute": "tools.traceroute",
    "tools.save_traceroute_profile": "tools.traceroute",
    "tools.delete_traceroute_profile": "tools.traceroute",
    "tools.traceroute_run": "tools.traceroute",
    "tools.port_scanner": "tools.port_scanner",
    "tools.save_port_scan_profile": "tools.port_scanner",
    "tools.delete_port_scan_profile": "tools.port_scanner",
    "tools.snmp_test": "tools.snmp_test",
    "tools.save_snmp_profile": "tools.snmp_test",
    "tools.delete_snmp_profile": "tools.snmp_test",
    "tools.certificate_inspector": "tools.certificate_inspector",
    "tools.speed_test": "tools.speed_test",
    "tools.speed_test_ping": "tools.speed_test",
    "tools.speed_test_download": "tools.speed_test",
    "tools.speed_test_upload": "tools.speed_test",
    "tools.subnet_excluder": "tools.subnet_excluder",
    "tools.ping_tool": "tools.ping",
    "tools.ping_run": "tools.ping",
    "tools.save_ping_profile": "tools.ping",
    "tools.delete_ping_profile": "tools.ping",
    "tools.dns_response": "tools.dns_response",
    "tools.save_dns_profile": "tools.dns_response",
    "tools.delete_dns_profile": "tools.dns_response",
    "tools.radius_test": "tools.radius_test",
    "tools.save_radius_profile": "tools.radius_test",
    "tools.delete_radius_profile": "tools.radius_test",
    "tools.multi_ssh": "tools.multi_ssh",
}


def tool_allowed(tool: ToolLink, *, is_admin: bool, allowed_tool_ids: set[str] | None = None) -> bool:
    if is_admin:
        return True
    allowed_tool_ids = allowed_tool_ids or set()
    return tool.id in allowed_tool_ids


def visible_tools(*, is_admin: bool, allowed_tool_ids: set[str] | None = None) -> list[ToolLink]:
    return [tool for tool in TOOLS if tool_allowed(tool, is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)]


def homepage_tools(*, is_admin: bool, allowed_tool_ids: set[str] | None = None) -> list[ToolLink]:
    return [
        tool
        for tool in visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
        if tool.show_on_home
    ]


def grouped_visible_tools(*, is_admin: bool, allowed_tool_ids: set[str] | None = None) -> list[tuple[str, list[ToolLink]]]:
    groups: dict[str, list[ToolLink]] = {}
    for tool in homepage_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids):
        groups.setdefault(tool.category_label, []).append(tool)
    return [(label, tools) for label, tools in groups.items()]


def grouped_access_tools() -> list[tuple[str, list[ToolLink]]]:
    groups: dict[str, list[ToolLink]] = {}
    for tool in TOOLS:
        if not tool.grantable:
            continue
        groups.setdefault(tool.category_label, []).append(tool)
    return [(label, tools) for label, tools in groups.items()]


def visible_tools_for_category(
    category: str, *, is_admin: bool, allowed_tool_ids: set[str] | None = None
) -> list[ToolLink]:
    return [
        tool
        for tool in visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
        if tool.category == category and tool.id != f"{category}.home"
    ]


def grouped_visible_tools_for_category(
    category: str, *, is_admin: bool, allowed_tool_ids: set[str] | None = None
) -> list[tuple[str, list[ToolLink]]]:
    groups: dict[str, list[ToolLink]] = {}
    for tool in visible_tools_for_category(
        category, is_admin=is_admin, allowed_tool_ids=allowed_tool_ids
    ):
        groups.setdefault(tool.category_label, []).append(tool)
    return [(label, tools) for label, tools in groups.items()]


def favorite_tools(
    favorite_ids: list[str], *, is_admin: bool, allowed_tool_ids: set[str] | None = None
) -> list[ToolLink]:
    visible = {
        tool.id: tool
        for tool in visible_tools(is_admin=is_admin, allowed_tool_ids=allowed_tool_ids)
    }
    return [visible[tool_id] for tool_id in favorite_ids if tool_id in visible]


def tool_id_for_endpoint(endpoint: str, view_args: dict[str, Any] | None = None) -> str | None:
    if endpoint in {"task_form", "task_csv_template", "run_task", "task_objects", "rename_objects", "task_fields", "task_preview"}:
        return TASK_TOOL_IDS.get(str((view_args or {}).get("task_id", "")))
    return ENDPOINT_TOOL_IDS.get(endpoint)
