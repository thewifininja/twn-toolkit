from __future__ import annotations

import secrets
import time
from urllib.parse import urlsplit

from flask import Blueprint, Response, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .diagnostic_tools import parse_http_headers, send_api_request
from .network_tools import ToolInputError
from .route_utils import disable_client_caching
from .investigation_context import record_current_investigation_event


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
        journal_event = None
        error = ""
        if request.method == "POST":
            operation_id = f"api-request:{secrets.token_hex(12)}"
            journal_started_at = time.time()
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
            target = _journal_api_origin(form["url"])
            safe_result = _journal_api_result(result)
            journal_event = record_current_investigation_event(
                operation_id=operation_id,
                event_type="diagnostic.failed" if error else "diagnostic.completed",
                tool_id="tools.api_request",
                action="API request",
                outcome="failed" if error else "succeeded",
                summary=(
                    f"API request failed: {error}"
                    if error
                    else f"Sent {form['method'].upper()} request to {target}: HTTP {result['status']}."
                ),
                targets={"origin": target},
                parameters={
                    "method": form["method"].upper(),
                    "timeout_seconds": form["timeout"],
                    "verify_tls": form["verify_tls"],
                    "request_header_names": _journal_header_names(form["headers"]),
                    "request_body_bytes": len(form["body"].encode("utf-8")),
                },
                metrics={
                    "status": safe_result.get("status"),
                    "elapsed_ms": safe_result.get("elapsed_ms"),
                    "response_bytes": safe_result.get("bytes"),
                    "response_truncated": safe_result.get("truncated"),
                }
                if safe_result
                else {},
                details={"error": error, "result": safe_result},
                started_at=journal_started_at,
                completed_at=time.time(),
            )
        response = Response(
            render_template(
                "tools/api_request.html",
                form=form,
                result=result,
                error=error,
                journal_event=journal_event,
            )
        )
        disable_client_caching(response)
        return response


def _journal_api_origin(url: str) -> str:
    try:
        parsed = urlsplit(url.strip())
        if not parsed.scheme or not parsed.hostname:
            return ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme.lower()}://{parsed.hostname}{port}"
    except ValueError:
        return ""


def _journal_api_result(result: dict | None) -> dict:
    if not result:
        return {}
    return {
        "status": result.get("status"),
        "reason": result.get("reason"),
        "elapsed_ms": result.get("elapsed_ms"),
        "resolved_addresses": result.get("resolved_addresses", []),
        "request_header_names": sorted((result.get("request_headers") or {}).keys()),
        "response_header_names": sorted((result.get("response_headers") or {}).keys()),
        "bytes": result.get("bytes"),
        "truncated": result.get("truncated"),
        "redirect_origin": _journal_api_origin(str(result.get("redirect", ""))),
    }


def _journal_header_names(source: str) -> list[str]:
    try:
        return sorted(parse_http_headers(source))
    except ToolInputError:
        return []
