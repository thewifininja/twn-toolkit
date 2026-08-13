from __future__ import annotations

import secrets
import time

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .investigation_context import record_current_investigation_event
from .network_tools import RFC1918_NETWORKS, ToolInputError, split_values, subtract_subnets


def register_subnet_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/subnet-excluder", methods=["GET", "POST"])
    def subnet_excluder():
        supernets = ""
        exclusions = ""
        results: list[str] | None = None
        error = ""
        journal_event = None
        if request.method == "POST":
            operation_id = f"subnet-exclusion:{secrets.token_hex(12)}"
            started_at = time.time()
            supernets = request.form.get("supernets", "").strip()
            exclusions = request.form.get("exclusions", "").strip()
            try:
                results = subtract_subnets(supernets, exclusions)
            except ToolInputError as exc:
                error = str(exc)
                record_current_activity("Addressing", "Calculated subnet exclusions", "Request failed")
            else:
                record_current_activity(
                    "Addressing",
                    "Calculated subnet exclusions",
                    f"Produced {len(results)} network(s)",
                    counters={"subnet": {"calculations": 1, "networks": len(results)}},
                )
                parent_networks = (
                    list(RFC1918_NETWORKS)
                    if supernets.casefold() == "rfc1918"
                    else split_values(supernets)
                )
                journal_event = record_current_investigation_event(
                    operation_id=operation_id,
                    event_type="diagnostic.completed",
                    tool_id="tools.subnet_excluder",
                    action="Subnet exclusion calculation",
                    outcome="succeeded",
                    summary=f"Calculated {len(results)} remaining network(s).",
                    targets={
                        "parent_networks": parent_networks,
                        "excluded_networks": split_values(exclusions),
                    },
                    parameters={},
                    metrics={"remaining_network_count": len(results)},
                    details={"remaining_networks": results},
                    started_at=started_at,
                    completed_at=time.time(),
                )
            annotate_tool_run(
                category="Network tools",
                action_namespace="subnet.exclusion",
                tool_name="subnet exclusion calculation",
                outcome="failed" if error else "succeeded",
                details={"result network count": len(results or [])},
            )
        return render_template(
            "tools/subnet_excluder.html",
            error=error,
            exclusions=exclusions,
            results=results,
            supernets=supernets,
            journal_event=journal_event,
        )
