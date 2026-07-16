from __future__ import annotations

from flask import Blueprint, redirect, url_for

from .api_request_routes import register_api_request_routes
from .certificate_routes import register_certificate_routes
from .dhcp_routes import register_dhcp_routes
from .dns_routes import register_dns_routes
from .ip_info_routes import register_ip_info_routes
from .ntp_routes import register_ntp_routes
from .packet_replay_routes import register_packet_replay_routes
from .path_mtu_routes import register_path_mtu_routes
from .ping_routes import register_ping_routes
from .port_scanner_routes import register_port_scanner_routes
from .radius_routes import register_radius_routes
from .snmp_routes import register_snmp_routes
from .speed_test_routes import register_speed_test_routes
from .sftp_routes import register_sftp_routes
from .ssh_routes import register_ssh_routes
from .subnet_routes import register_subnet_routes
from .syslog_routes import register_syslog_routes
from .traceroute_routes import register_traceroute_routes


tools_bp = Blueprint("tools", __name__, url_prefix="/tools")
register_api_request_routes(tools_bp)
register_certificate_routes(tools_bp)
register_dhcp_routes(tools_bp)
register_dns_routes(tools_bp)
register_ip_info_routes(tools_bp)
register_ntp_routes(tools_bp)
register_packet_replay_routes(tools_bp)
register_path_mtu_routes(tools_bp)
register_ping_routes(tools_bp)
register_port_scanner_routes(tools_bp)
register_radius_routes(tools_bp)
register_snmp_routes(tools_bp)
register_speed_test_routes(tools_bp)
register_sftp_routes(tools_bp)
register_ssh_routes(tools_bp)
register_subnet_routes(tools_bp)
register_syslog_routes(tools_bp)
register_traceroute_routes(tools_bp)


@tools_bp.get("/")
def index():
    return redirect(url_for("index"))
