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
        "apply_switch_order",
        "apply_raspberry_pi_networking",
        "bulk_delete_datastore_files",
        "bulk_download_datastore_files",
        "bulk_move_datastore_files",
        "change_user_password",
        "cleanup_orphan_artifacts",
        "clear_automation_runs",
        "clear_ftp_history",
        "clear_ssh_transfer_history",
        "clear_tftp_history",
        "confirm_raspberry_pi_networking",
        "create_datastore_folder",
        "create_investigation",
        "import_investigation_case",
        "merge_investigation_case",
        "create_user",
        "create_recovery_point",
        "delete_access_profile",
        "delete_raspberry_pi_network_profile",
        "delete_automation",
        "delete_automation_action",
        "delete_automation_condition",
        "delete_automation_schedule",
        "delete_automation_run",
        "delete_datastore_entry",
        "delete_fortiauthenticator_profile",
        "delete_ftp_temporary_file",
        "delete_profile",
        "delete_ssh_transfer_temporary_file",
        "delete_tftp_temporary_file",
        "delete_user",
        "disable_raspberry_pi_networking",
        "duplicate_access_profile",
        "duplicate_automation",
        "duplicate_automation_action",
        "duplicate_automation_condition",
        "duplicate_automation_schedule",
        "duplicate_fortiauthenticator_profile",
        "duplicate_profile",
        "execute_fortiauthenticator_mac_cleanup",
        "export_fortiauthenticator_mac_devices",
        "export_fortiauthenticator_mac_group_memberships",
        "export_profile_backup",
        "inspect_configuration_backup",
        "import_profile_backup",
        "install_update",
        "add_investigation_note",
        "add_investigation_participant",
        "add_automation_run_to_case",
        "login",
        "logout",
        "optimize_automation_database",
        "prune_automation_history",
        "rename_datastore_entry",
        "reset_activity_metric",
        "reset_activity_scoreboard",
        "reset_activity_user_score",
        "reset_dashboard_layout",
        "retry_failed_automation_jobs",
        "rollback_update",
        "rollback_raspberry_pi_networking",
        "run_automation_now",
        "save_access_profile",
        "save_automation",
        "save_automation_action",
        "save_automation_condition",
        "save_automation_schedule",
        "save_dashboard_layout",
        "save_fortiauthenticator_profile",
        "save_ftp_settings",
        "save_profile",
        "save_ssh_transfer_settings",
        "save_tftp_settings",
        "setup",
        "test_automation_condition",
        "test_condition_definition",
        "test_schedule_definition",
        "test_smtp_settings",
        "toggle_raspberry_pi_network_profile",
        "test_fortiauthenticator_profile",
        "test_profile",
        "toggle_automation",
        "update_smtp_settings",
        "tools.start_snmp_interface_monitor",
        "tools.start_ping_session",
        "tools.start_remote_terminal_session",
        "tools.attach_remote_terminal_case",
        "tools.bulk_update_remote_terminal_library",
        "tools.create_remote_terminal_credential",
        "tools.create_remote_terminal_folder",
        "tools.create_remote_terminal_host",
        "tools.import_remote_terminal_hosts",
        "tools.delete_remote_terminal_credential",
        "tools.delete_remote_terminal_folder",
        "tools.delete_remote_terminal_host",
        "tools.delete_remote_terminal_scrollback",
        "tools.duplicate_remote_terminal_credential",
        "tools.duplicate_remote_terminal_folder",
        "tools.duplicate_remote_terminal_host",
        "tools.rename_live_tool_session",
        "tools.rename_remote_terminal_session",
        "tools.save_remote_terminal_scrollback",
        "tools.stop_live_tool_session",
        "tools.stop_remote_terminal_session",
        "tools.update_remote_terminal_credential",
        "tools.update_remote_terminal_folder",
        "tools.update_remote_terminal_host",
        "tools.delete_dns_profile",
        "tools.delete_ntp_profile",
        "tools.delete_ping_profile",
        "tools.delete_port_scan_profile",
        "tools.delete_radius_profile",
        "tools.delete_snmp_profile",
        "tools.delete_ssh_commandlet",
        "tools.delete_traceroute_profile",
        "tools.retry_multi_ssh_host_key",
        "tools.api_request",
        "tools.cancel_acme_dns_request",
        "tools.certificate_inspector",
        "tools.collect_pending_certificate",
        "tools.continue_acme_dns_request",
        "tools.delete_managed_certificate",
        "tools.delete_pki_credential",
        "tools.delete_pki_server",
        "tools.delete_pki_template",
        "tools.dhcp_discover",
        "tools.dns_response",
        "tools.clear_iperf3_server_results",
        "tools.iperf3",
        "tools.start_iperf3_server",
        "tools.stop_iperf3_server",
        "tools.multi_ssh",
        "tools.multi_transfer",
        "tools.multicast",
        "tools.multicast_live",
        "tools.ntp_test",
        "tools.path_mtu",
        "tools.start_packet_capture",
        "tools.start_acme_dns_request",
        "tools.stop_packet_capture",
        "tools.save_packet_capture",
        "tools.delete_packet_capture",
        "tools.port_scanner",
        "tools.radius_test",
        "tools.record_ip_snapshot",
        "tools.enroll_managed_certificate",
        "tools.speed_test_activity",
        "tools.save_dns_profile",
        "tools.save_ntp_profile",
        "tools.save_ping_profile",
        "tools.save_port_scan_profile",
        "tools.save_radius_profile",
        "tools.save_pki_credential",
        "tools.save_pki_server",
        "tools.save_pki_template",
        "tools.save_snmp_profile",
        "tools.save_traceroute_profile",
        "tools.save_wol_profile",
        "tools.snmp_test",
        "tools.subnet_excluder",
        "tools.syslog_receiver",
        "tools.test_pki_server",
        "tools.traceroute",
        "tools.traceroute_run",
        "tools.update_ping_session_targets",
        "tools.update_snmp_interface_monitor_session",
        "tools.wake_on_lan",
        "tools.delete_wol_profile",
        "tools.delete_lldp_persona",
        "tools.duplicate_lldp_persona",
        "tools.stop_lldp_session",
        "tools.duplicate_dns_profile",
        "tools.duplicate_ntp_profile",
        "tools.duplicate_ping_profile",
        "tools.duplicate_pki_credential",
        "tools.duplicate_pki_server",
        "tools.duplicate_pki_template",
        "tools.duplicate_port_scan_profile",
        "tools.duplicate_radius_profile",
        "tools.duplicate_snmp_profile",
        "tools.duplicate_traceroute_profile",
        "tools.duplicate_wol_profile",
        "update_automation_retention",
        "update_investigation_state",
        "remove_investigation_participant",
        "update_investigation_report_contents",
        "update_operational_settings",
        "update_server_settings",
        "update_session_settings",
        "update_time_settings",
        "update_user_access",
        "upload_update_bundle",
        "upload_datastore_files",
        "upload_ftp_temporary_file",
        "upload_investigation_evidence",
        "upload_ssh_transfer_temporary_file",
        "upload_tftp_temporary_file",
    }
)


# A conditional endpoint deliberately annotates lifecycle boundaries while
# suppressing its high-frequency intermediate messages.
AUDIT_CONDITIONAL_ENDPOINTS = frozenset(
    {
        "rename_objects",
        "run_task",
        "tools.packet_replay",
        "tools.lldp_lab",
        "tools.ping_activity",
    }
)


AUDIT_SUPPRESSED_ENDPOINTS = frozenset(
    {
        "tools.import_ssh_hosts",
        "tools.ping_run",
        "tools.ping_validate_targets",
        "tools.check_acme_dns_request",
        "tools.multi_sftp",
        "tools.speed_test_upload",
        "fortiap_client_history",
        "fortiauthenticator_mac_cleanup",
        "fortiauthenticator_mac_devices",
        "fortiauthenticator_mac_group_memberships",
        "switch_order_objects",
        "task_fields",
        "task_objects",
        "task_preview",
        "tools.snmp_interface_sample",
        "tools.snmp_interface_samples",
        "tools.snmp_interfaces",
        "tools.remote_terminal_input",
        "tools.remote_terminal_credential",
        "tools.save_remote_terminal_checkpoint",
        "tools.resize_remote_terminal_session",
        "tools.preview_remote_terminal_host_import",
        "scan_raspberry_pi_wifi",
    }
)


# Exclusions are reserved for authenticated personal presentation preferences,
# not operational work. Public authentication lifecycle routes remain pending
# until they receive a deliberate security-audit design.
AUDIT_EXCLUDED_ENDPOINTS = {
    "reorder_tool_favorites": "Personal navigation preference with no operational effect.",
    "toggle_tool_favorite": "Personal navigation preference with no operational effect.",
    "update_appearance": "Personal presentation preference with no operational effect.",
    "update_theme": "Personal presentation preference with no operational effect.",
}


# This is an explicit burn-down list, not a permanent allowlist. Later audit
# enrichment changes move endpoints from here into one of the resolved policies.
AUDIT_PENDING_ENDPOINTS = frozenset()


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
