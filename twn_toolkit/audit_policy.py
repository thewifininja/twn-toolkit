from __future__ import annotations

from enum import Enum


MUTATING_HTTP_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class AuditRoutePolicy(str, Enum):
    """Required audit disposition for an endpoint that accepts mutations."""

    ANNOTATED = "annotated"
    CONDITIONAL = "conditional"
    SUPPRESSED = "suppressed"
    EXCLUDED = "excluded"
    PENDING = "pending"


# These routes already attach a curated event after a successful meaningful
# operation. Keep the list explicit: adding another mutating route must require
# a conscious audit-policy decision in the route's pull request.
AUDIT_ANNOTATED_ENDPOINTS = frozenset(
    {
        "bulk_delete_datastore_files",
        "bulk_download_datastore_files",
        "bulk_move_datastore_files",
        "change_user_password",
        "cleanup_orphan_artifacts",
        "clear_automation_runs",
        "clear_ftp_history",
        "clear_ssh_transfer_history",
        "clear_tftp_history",
        "create_datastore_folder",
        "create_user",
        "delete_access_profile",
        "delete_automation",
        "delete_automation_action",
        "delete_automation_condition",
        "delete_automation_run",
        "delete_datastore_entry",
        "delete_ftp_temporary_file",
        "delete_ssh_transfer_temporary_file",
        "delete_tftp_temporary_file",
        "delete_user",
        "export_profile_backup",
        "import_profile_backup",
        "optimize_automation_database",
        "prune_automation_history",
        "rename_datastore_entry",
        "reset_activity_metric",
        "reset_activity_scoreboard",
        "reset_activity_user_score",
        "reset_dashboard_layout",
        "run_automation_now",
        "save_access_profile",
        "save_automation",
        "save_automation_action",
        "save_automation_condition",
        "save_dashboard_layout",
        "save_ftp_settings",
        "save_ssh_transfer_settings",
        "save_tftp_settings",
        "test_automation_condition",
        "test_condition_definition",
        "toggle_automation",
        "tools.start_snmp_interface_monitor",
        "tools.stop_snmp_interface_monitor",
        "update_automation_retention",
        "update_operational_settings",
        "update_server_settings",
        "update_session_settings",
        "update_user_access",
        "upload_datastore_files",
        "upload_ftp_temporary_file",
        "upload_ssh_transfer_temporary_file",
        "upload_tftp_temporary_file",
    }
)


# A conditional endpoint deliberately annotates lifecycle boundaries while
# suppressing its high-frequency intermediate messages.
AUDIT_CONDITIONAL_ENDPOINTS = frozenset({"tools.ping_activity"})


AUDIT_SUPPRESSED_ENDPOINTS = frozenset(
    {
        "tools.ping_run",
        "tools.ping_validate_targets",
        "tools.snmp_interface_sample",
        "tools.snmp_interface_samples",
        "tools.snmp_interfaces",
    }
)


# Exclusions are reserved for authenticated personal presentation preferences,
# not operational work. Public authentication lifecycle routes remain pending
# until they receive a deliberate security-audit design.
AUDIT_EXCLUDED_ENDPOINTS = {
    "toggle_tool_favorite": "Personal navigation preference with no operational effect.",
    "update_theme": "Personal presentation preference with no operational effect.",
}


# This is an explicit burn-down list, not a permanent allowlist. Later audit
# enrichment changes move endpoints from here into one of the resolved policies.
AUDIT_PENDING_ENDPOINTS = frozenset(
    {
        "apply_switch_order",
        "delete_fortiauthenticator_profile",
        "delete_profile",
        "execute_fortiauthenticator_mac_cleanup",
        "export_fortiauthenticator_mac_devices",
        "export_fortiauthenticator_mac_group_memberships",
        "fortiap_client_history",
        "fortiauthenticator_mac_cleanup",
        "fortiauthenticator_mac_devices",
        "fortiauthenticator_mac_group_memberships",
        "login",
        "logout",
        "rename_objects",
        "run_task",
        "save_fortiauthenticator_profile",
        "save_profile",
        "setup",
        "switch_order_objects",
        "task_fields",
        "task_objects",
        "task_preview",
        "test_fortiauthenticator_profile",
        "test_profile",
        "tools.api_request",
        "tools.certificate_inspector",
        "tools.delete_dns_profile",
        "tools.delete_ntp_profile",
        "tools.delete_ping_profile",
        "tools.delete_port_scan_profile",
        "tools.delete_radius_profile",
        "tools.delete_snmp_profile",
        "tools.delete_traceroute_profile",
        "tools.dhcp_discover",
        "tools.dns_response",
        "tools.multi_sftp",
        "tools.multi_ssh",
        "tools.multi_transfer",
        "tools.ntp_test",
        "tools.packet_replay",
        "tools.path_mtu",
        "tools.port_scanner",
        "tools.radius_test",
        "tools.save_dns_profile",
        "tools.save_ntp_profile",
        "tools.save_ping_profile",
        "tools.save_port_scan_profile",
        "tools.save_radius_profile",
        "tools.save_snmp_profile",
        "tools.save_traceroute_profile",
        "tools.snmp_test",
        "tools.speed_test_activity",
        "tools.speed_test_upload",
        "tools.subnet_excluder",
        "tools.syslog_receiver",
        "tools.traceroute",
        "tools.traceroute_run",
    }
)


def mutation_audit_policies() -> dict[str, AuditRoutePolicy]:
    groups = {
        AuditRoutePolicy.ANNOTATED: AUDIT_ANNOTATED_ENDPOINTS,
        AuditRoutePolicy.CONDITIONAL: AUDIT_CONDITIONAL_ENDPOINTS,
        AuditRoutePolicy.SUPPRESSED: AUDIT_SUPPRESSED_ENDPOINTS,
        AuditRoutePolicy.EXCLUDED: frozenset(AUDIT_EXCLUDED_ENDPOINTS),
        AuditRoutePolicy.PENDING: AUDIT_PENDING_ENDPOINTS,
    }
    policies: dict[str, AuditRoutePolicy] = {}
    for policy, endpoints in groups.items():
        for endpoint in endpoints:
            if endpoint in policies:
                raise RuntimeError(
                    f"Audit endpoint {endpoint!r} has both {policies[endpoint]} and {policy} policies."
                )
            policies[endpoint] = policy
    return policies
