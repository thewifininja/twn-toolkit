from __future__ import annotations

import ipaddress
import secrets
import time

import requests
from flask import Blueprint, Response, jsonify, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .investigation_context import record_current_investigation_event
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

    @tools_bp.get("/whats-my-ip/server-public")
    def server_public_ip():
        try:
            upstream = requests.get(
                "https://api64.ipify.org?format=json",
                headers={"Accept": "application/json"},
                timeout=8,
                allow_redirects=False,
            )
            upstream.raise_for_status()
            address = str(upstream.json().get("ip", "")).strip()
            version = ipaddress.ip_address(address).version
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            response = jsonify(
                {"error": "The toolkit server could not determine its public IP address."}
            )
            response.status_code = 502
        else:
            response = jsonify({"ip": address, "family": f"IPv{version}"})
        disable_client_caching(response)
        return response

    @tools_bp.post("/whats-my-ip/case-snapshot")
    def record_ip_snapshot():
        addresses = {
            "toolkit_facing": _valid_address(request.remote_addr),
            "browser_public": _valid_address(request.form.get("browser_public", "")),
            "server_public": _valid_address(request.form.get("server_public", "")),
        }
        addresses = {key: value for key, value in addresses.items() if value}
        now = time.time()
        event = record_current_investigation_event(
            operation_id=f"ip-snapshot:{secrets.token_hex(12)}",
            event_type="diagnostic.snapshot",
            tool_id="tools.whats_my_ip",
            action="IP address snapshot",
            outcome="succeeded",
            summary=f"Retained an IP address snapshot with {len(addresses)} observation(s).",
            targets=addresses,
            parameters={
                key: f"IPv{ipaddress.ip_address(value).version}"
                for key, value in addresses.items()
            },
            metrics={"address_count": len(addresses)},
            details={},
            started_at=now,
            completed_at=now,
        )
        annotate_tool_run(
            category="Network tools",
            action_namespace="ip.snapshot",
            tool_name="IP address snapshot",
            outcome="succeeded" if event else "not_recorded",
            details={"address count": len(addresses)},
        )
        response = jsonify(
            {
                "case_recorded": bool(event),
                "message": (
                    "Recorded this IP snapshot in the active case."
                    if event
                    else "Open or resume a recording case before adding a snapshot."
                ),
            }
        )
        if not event:
            response.status_code = 409
        disable_client_caching(response)
        return response


def _valid_address(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""
