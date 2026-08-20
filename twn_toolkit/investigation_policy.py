from __future__ import annotations

from dataclasses import dataclass


CAPTURE_MODES = frozenset(
    {"native", "finite", "lifecycle", "hybrid", "action", "explicit", "excluded"}
)


@dataclass(frozen=True)
class InvestigationCapturePolicy:
    mode: str
    evidence: str
    rationale: str

    def __post_init__(self) -> None:
        if self.mode not in CAPTURE_MODES:
            raise ValueError(f"Unknown investigation capture mode: {self.mode}")


def _policy(mode: str, evidence: str, rationale: str) -> InvestigationCapturePolicy:
    return InvestigationCapturePolicy(mode, evidence, rationale)


CAPTURE_POLICIES: dict[str, InvestigationCapturePolicy] = {
    "fortigate.home": _policy("excluded", "none", "Navigation is not case evidence."),
    "fortigate.wireless_client_history": _policy("finite", "bounded-results", "A client-history search is a troubleshooting observation."),
    "fortigate.rename_aps": _policy("action", "bounded-results", "Configuration changes belong in the case narrative."),
    "fortigate.export_aps": _policy("action", "generated-export", "An intentional inventory export can support a case."),
    "fortigate.export_wireless_clients": _policy("action", "generated-export", "An intentional client export can support a case."),
    "fortigate.switch_order": _policy("action", "bounded-results", "Managed-switch ordering changes network state."),
    "fortigate.rename_switches": _policy("action", "bounded-results", "Configuration changes belong in the case narrative."),
    "fortigate.export_switches": _policy("action", "generated-export", "An intentional inventory export can support a case."),
    "fortigate.export_fortiswitch_clients": _policy("action", "generated-export", "An intentional client export can support a case."),
    "fortiauthenticator.home": _policy("excluded", "none", "Navigation is not case evidence."),
    "fortiauthenticator.mac_devices": _policy("action", "generated-export", "An intentional device export can support a case."),
    "fortiauthenticator.group_memberships": _policy("action", "generated-export", "An intentional membership export can support a case."),
    "fortiauthenticator.mac_cleanup": _policy("action", "bounded-results", "Cleanup changes external authentication state."),
    "investigations.workspace": _policy("native", "case-store", "This is the case workspace itself."),
    "tools.whats_my_ip": _policy("explicit", "snapshot", "Page views must not create journal noise."),
    "tools.subnet_excluder": _policy("finite", "bounded-results", "A submitted calculation is an intentional finite observation."),
    "tools.ping": _policy("lifecycle", "csv", "Persistent samples require lifecycle boundaries and bounded evidence."),
    "tools.multi_ssh": _policy("finite", "generated-output", "Executed commands and per-host outcomes are meaningful work."),
    "tools.remote_terminal": _policy("lifecycle", "transcript", "Interactive shells need explicit boundaries and optional bounded transcript evidence."),
    "tools.multi_sftp": _policy("finite", "result-manifest", "Transfer outcomes matter without duplicating every payload."),
    "tools.dns_response": _policy("finite", "bounded-results", "DNS results are finite structured observations."),
    "tools.radius_test": _policy("finite", "redacted-results", "Authentication outcomes matter; credentials never do."),
    "tools.speed_test": _policy("finite", "bounded-results", "Browser throughput results are finite observations."),
    "tools.iperf3": _policy("hybrid", "bounded-results", "Client tests are finite while managed servers have a lifecycle."),
    "tools.multicast": _policy("finite", "bounded-results", "Each authorized test has a bounded result."),
    "tools.lldp_lab": _policy("hybrid", "json", "Neighbor snapshots are explicit evidence while bounded identity emission has lifecycle boundaries."),
    "tools.certificate_inspector": _policy("finite", "bounded-results", "TLS identity, trust, and chain findings are reportable."),
    "tools.certificate_automation": _policy("action", "status-events", "Issuance and installation actions are consequential workflow boundaries."),
    "tools.snmp_test": _policy("hybrid", "csv", "OID polls are finite while interface monitors are persistent."),
    "tools.port_scanner": _policy("finite", "bounded-results", "Port scan results are finite observations."),
    "tools.ntp_test": _policy("finite", "bounded-results", "NTP results are finite observations."),
    "tools.dhcp_discover": _policy("finite", "bounded-results", "Offers are finite network evidence."),
    "tools.wake_on_lan": _policy("action", "bounded-results", "Wake attempts and verification are consequential actions."),
    "tools.packet_capture": _policy("lifecycle", "pcap", "Capture boundaries and original packets are evidence."),
    "tools.packet_replay": _policy("action", "bounded-results", "Authorized frame injection changes network traffic."),
    "tools.path_mtu": _policy("finite", "bounded-results", "Path MTU results are finite observations."),
    "tools.api_request": _policy("finite", "redacted-results", "HTTP outcomes matter but secrets and bodies need protection."),
    "tools.syslog_receiver": _policy("finite", "generated-output", "Bounded send/listen runs produce reportable results."),
    "tools.traceroute": _policy("finite", "bounded-results", "Each completed trace is a finite observation."),
    "automation.home": _policy("explicit", "generated-run", "Background runs have no implicit owner case; collected runs can be attached deliberately."),
    "automation.schedules": _policy("excluded", "none", "Schedule configuration belongs in the audit log."),
    "automation.conditions": _policy("excluded", "none", "Condition configuration belongs in the audit log."),
    "automation.actions": _policy("excluded", "none", "Action configuration belongs in the audit log."),
    "local.datastore": _policy("explicit", "attachment", "Files enter a case only through deliberate evidence attachment."),
    "local.file_transfers": _policy("explicit", "attachment", "Listener configuration is audit data; received files may be attached."),
    "admin.settings": _policy("excluded", "none", "Administrative configuration is not automatic case evidence."),
    "admin.diagnostics": _policy("explicit", "snapshot", "A system-health snapshot should be deliberately attached."),
    "admin.updates": _policy("excluded", "none", "Release operations belong in the system audit trail."),
}


def capture_policy(tool_id: str) -> InvestigationCapturePolicy:
    try:
        return CAPTURE_POLICIES[tool_id]
    except KeyError as exc:
        raise KeyError(f"Tool {tool_id!r} has no investigation capture policy.") from exc
