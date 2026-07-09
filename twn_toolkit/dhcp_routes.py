from __future__ import annotations

from flask import Blueprint, render_template, request

from .dhcp_tools import (
    DEFAULT_PARAMETER_REQUEST_LIST,
    DHCP_OPTIONS,
    available_interfaces,
    discover_offers,
    format_parameter_request_list,
    parse_parameter_request_list,
)
from .network_tools import ToolInputError


def register_dhcp_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/dhcp-discover", methods=["GET", "POST"])
    def dhcp_discover():
        interfaces = available_interfaces()
        default_interface = interfaces[0] if interfaces else {"name": "", "mac": ""}
        form = {
            "interface": default_interface["name"],
            "mac": default_interface["mac"],
            "parameters": format_parameter_request_list(DEFAULT_PARAMETER_REQUEST_LIST),
            "timeout": "3",
            "hostname": "",
            "vendor_class": "",
        }
        offers = None
        requested_codes = list(DEFAULT_PARAMETER_REQUEST_LIST)
        error = ""
        if request.method == "POST":
            form = {
                "interface": request.form.get("interface", "").strip(),
                "mac": request.form.get("mac", "").strip(),
                "parameters": request.form.get("parameters", "").strip(),
                "timeout": request.form.get("timeout", "3").strip(),
                "hostname": request.form.get("hostname", "").strip(),
                "vendor_class": request.form.get("vendor_class", "").strip(),
            }
            try:
                requested_codes = parse_parameter_request_list(form["parameters"])
                offers = discover_offers(
                    form["interface"],
                    form["mac"],
                    requested_codes,
                    timeout=float(form["timeout"]),
                    hostname=form["hostname"],
                    vendor_class=form["vendor_class"],
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid DHCP probe settings."
        return render_template(
            "tools/dhcp_discover.html",
            error=error,
            form=form,
            interfaces=interfaces,
            offers=offers,
            requested_codes=requested_codes,
            option_names=DHCP_OPTIONS,
        )
