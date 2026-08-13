from __future__ import annotations

import secrets
import time
from datetime import date, datetime
from typing import Any

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .certificate_tools import (
    CertificateInspectionError,
    inspect_certificate_chain,
    normalize_certificate_target,
)
from .investigation_context import record_current_investigation_event


def register_certificate_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/certificate-inspector", methods=["GET", "POST"])
    def certificate_inspector():
        form = {"target": "", "port": "443", "timeout": "8"}
        result = None
        journal_event = None
        error = ""
        if request.method == "POST":
            operation_id = f"certificate-inspection:{secrets.token_hex(12)}"
            journal_started_at = time.time()
            host = ""
            port = 0
            form = {key: request.form.get(key, "").strip() for key in form}
            try:
                host, port = normalize_certificate_target(form["target"], form["port"])
                timeout = float(form["timeout"])
                result = inspect_certificate_chain(host, port, timeout)
                form["port"] = str(port)
            except (CertificateInspectionError, ValueError) as exc:
                error = str(exc)
                record_current_activity("TLS", "Inspected certificate chain", "Request failed")
            else:
                record_current_activity(
                    "TLS",
                    "Inspected certificate chain",
                    f"{host}:{port} · {result.get('presented_count', 0)} certificate(s)",
                    counters={"certificates": {"inspections": 1}},
                )
            annotate_tool_run(
                category="Network tools",
                action_namespace="tls.certificate_inspection",
                tool_name="certificate inspection",
                outcome="failed" if error else "succeeded",
                details={
                    "presented certificate count": (
                        int(result.get("presented_count", 0)) if result else 0
                    ),
                },
            )
            safe_result = _journal_certificate_result(result)
            if error:
                journal_summary = f"Certificate inspection failed: {error}"
            else:
                overall = "valid" if result.get("overall_valid") else "needs attention"
                journal_summary = (
                    f"Inspected TLS at {host}:{port}: "
                    f"{result.get('presented_count', 0)} certificate(s), {overall}."
                )
            journal_event = record_current_investigation_event(
                operation_id=operation_id,
                event_type="diagnostic.failed" if error else "diagnostic.completed",
                tool_id="tools.certificate_inspector",
                action="Certificate inspection",
                outcome="failed" if error else "succeeded",
                summary=journal_summary,
                targets={"host": host, "port": port},
                parameters={"timeout_seconds": form["timeout"]},
                metrics={
                    "presented_certificates": result.get("presented_count", 0),
                    "elapsed_ms": result.get("elapsed_ms"),
                    "overall_valid": bool(result.get("overall_valid")),
                    "system_trust_valid": bool(result.get("trust", {}).get("valid")),
                    "hostname_valid": bool(result.get("hostname", {}).get("valid")),
                    "chain_order_valid": bool(result.get("chain_order_valid")),
                }
                if result
                else {},
                details={"error": error, "result": safe_result},
                started_at=journal_started_at,
                completed_at=time.time(),
            )
        return render_template(
            "tools/certificate_inspector.html",
            error=error,
            form=form,
            result=result,
            journal_event=journal_event,
        )


def _journal_certificate_result(result: dict[str, Any] | None) -> dict[str, Any]:
    if not result:
        return {}
    retained = {
        key: result.get(key)
        for key in (
            "host",
            "port",
            "elapsed_ms",
            "tls",
            "presented_count",
            "chain_order_valid",
            "order_checks",
            "server_sent_self_issued_root",
            "likely_missing_intermediate",
            "hostname",
            "trust",
            "overall_valid",
        )
    }
    retained["certificates"] = [
        {
            key: _journal_scalar(certificate.get(key))
            for key in (
                "position",
                "role",
                "subject",
                "common_name",
                "issuer",
                "serial_number",
                "not_before",
                "not_after",
                "time_valid",
                "days_remaining",
                "is_ca",
                "is_self_issued",
                "san_dns",
                "san_ip",
                "san_uri",
                "public_key",
                "signature_algorithm",
                "signature_hash",
                "sha256_fingerprint",
            )
        }
        for certificate in result.get("certificates", [])
        if isinstance(certificate, dict)
    ]
    return retained


def _journal_scalar(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_journal_scalar(item) for item in value]
    return str(value)
