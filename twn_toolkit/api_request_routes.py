from __future__ import annotations

from flask import Blueprint, Response, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .diagnostic_tools import parse_http_headers, send_api_request
from .network_tools import ToolInputError
from .route_utils import disable_client_caching


def register_api_request_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/api-request", methods=["GET", "POST"])
    def api_request():
        form = {
            "method": "GET",
            "url": "",
            "headers": "Accept: application/json",
            "body": "",
            "timeout": "10",
            "verify_tls": True,
        }
        result = None
        error = ""
        if request.method == "POST":
            form = {
                "method": request.form.get("method", "GET"),
                "url": request.form.get("url", "").strip(),
                "headers": request.form.get("headers", ""),
                "body": request.form.get("body", ""),
                "timeout": request.form.get("timeout", "10").strip(),
                "verify_tls": request.form.get("verify_tls") == "on",
            }
            try:
                result = send_api_request(
                    form["method"],
                    form["url"],
                    headers=parse_http_headers(form["headers"]),
                    body=form["body"],
                    timeout=float(form["timeout"]),
                    verify_tls=form["verify_tls"],
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid API request settings."
                record_current_activity("HTTP", "Sent API request", "Request failed")
            else:
                record_current_activity(
                    "HTTP",
                    "Sent API request",
                    f"{form['method']} · HTTP {result['status']}",
                    counters={"api": {"requests": 1}},
                )
            annotate_tool_run(
                category="Network tools",
                action_namespace="http.api_request",
                tool_name="API request",
                outcome="failed" if error else "succeeded",
                details={
                    "HTTP method": str(form["method"]).upper(),
                    "remote status code": result.get("status") if result else None,
                    "TLS verification enabled": bool(form["verify_tls"]),
                },
            )
        response = Response(
            render_template("tools/api_request.html", form=form, result=result, error=error)
        )
        disable_client_caching(response)
        return response
