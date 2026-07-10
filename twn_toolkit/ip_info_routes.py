from __future__ import annotations

import ipaddress

from flask import Blueprint, Response, render_template, request

from .activity_context import record_current_activity
from .route_utils import disable_client_caching


def register_ip_info_routes(tools_bp: Blueprint) -> None:
    @tools_bp.get("/whats-my-ip")
    def whats_my_ip():
        address = request.remote_addr or "Unavailable"
        try:
            version = f"IPv{ipaddress.ip_address(address).version}"
        except ValueError:
            version = "Unknown address family"
        record_current_activity(
            "Addressing",
            "Checked toolkit-facing IP",
            version,
            counters={"ip": {"lookups": 1}},
        )
        response = Response(
            render_template(
                "tools/whats_my_ip.html",
                client_ip=address,
                address_family=version,
            )
        )
        disable_client_caching(response)
        return response
