from __future__ import annotations

import secrets
import time

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .diagnostic_tools import test_path_mtu
from .investigation_context import record_current_investigation_event
from .network_tools import ToolInputError


def register_path_mtu_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/path-mtu", methods=["GET", "POST"])
    def path_mtu():
        form = {
            "host": "",
            "family": "auto",
            "minimum": "576",
            "maximum": "1500",
            "timeout": "1",
        }
        result = None
        journal_event = None
        error = ""
        if request.method == "POST":
            operation_id = f"path-mtu:{secrets.token_hex(12)}"
            journal_started_at = time.time()
            form = {
                key: request.form.get(key, default).strip()
                for key, default in form.items()
            }
            try:
                result = test_path_mtu(
                    form["host"],
                    family=form["family"],
                    minimum=int(form["minimum"]),
                    maximum=int(form["maximum"]),
                    timeout=float(form["timeout"]),
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid Path MTU settings."
                record_current_activity("Pathing", "Ran Path MTU test", "Request failed")
            else:
                record_current_activity(
                    "Pathing",
                    "Ran Path MTU test",
                    f"{result['host']}: {result['mtu']} bytes",
                    counters={
                        "path_mtu": {
                            "tests": 1,
                            "probes": len(result.get("probes", [])),
                        }
                    },
                )
            annotate_tool_run(
                category="Network tools",
                action_namespace="path_mtu",
                tool_name="Path MTU test",
                outcome="failed" if error else "succeeded",
                details={
                    "address family": form["family"],
                    "probe count": len(result.get("probes", [])) if result else 0,
                    "discovered MTU": result.get("mtu") if result else None,
                },
            )
            if error:
                journal_summary = f"Path MTU test failed: {error}"
                journal_metrics = {}
            else:
                conclusive = bool(result and result.get("conclusive"))
                journal_summary = (
                    f"Tested path MTU to {result['host']}: "
                    + (
                        f"largest working MTU was {result['mtu']} bytes."
                        if conclusive
                        else "the result was inconclusive."
                    )
                )
                journal_metrics = {
                    "mtu": result.get("mtu") if conclusive else None,
                    "probe_count": len(result.get("probes", [])),
                    "conclusive": conclusive,
                }
            journal_event = record_current_investigation_event(
                operation_id=operation_id,
                event_type="diagnostic.failed" if error else "diagnostic.completed",
                tool_id="tools.path_mtu",
                action="Path MTU test",
                outcome="failed" if error else "succeeded",
                summary=journal_summary,
                targets={"host": result.get("host") if result else ""},
                parameters={
                    "family": form["family"],
                    "minimum_mtu": form["minimum"],
                    "maximum_mtu": form["maximum"],
                    "timeout_seconds": form["timeout"],
                },
                metrics=journal_metrics,
                details={
                    "error": error,
                    "result": result or {},
                    "host": result.get("host") if result else "",
                },
                started_at=journal_started_at,
                completed_at=time.time(),
            )
        return render_template(
            "tools/path_mtu.html",
            form=form,
            result=result,
            error=error,
            journal_event=journal_event,
        )
