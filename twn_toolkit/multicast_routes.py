from __future__ import annotations

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .multicast_tools import (
    MULTICAST_MAX_DURATION_SECONDS,
    MULTICAST_MAX_MEGABITS,
    MULTICAST_MAX_PACKETS_PER_SECOND,
    MULTICAST_MAX_PACKET_SIZE,
    MULTICAST_MIN_PACKET_SIZE,
    multicast_capability,
    run_multicast_test,
)
from .network_tools import ToolInputError


def register_multicast_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/multicast", methods=["GET", "POST"])
    def multicast():
        capability = multicast_capability()
        interfaces = capability["interfaces"]
        first_interface = str(interfaces[0]["name"]) if interfaces else ""
        form: dict[str, object] = {
            "mode": "listen",
            "group": "239.255.10.10",
            "port": "5000",
            "duration": "10",
            "membership": "asm",
            "source": "",
            "receive_interface": first_interface,
            "send_interface": first_interface,
            "stream_format": "generic",
            "rtp_clock_rate": "90000",
            "packet_size": "1200",
            "rate": "1",
            "rate_unit": "mbps",
            "ttl": "8",
            "dscp": "0",
            "source_port": "0",
            "loopback": False,
            "authorized": False,
        }
        result = None
        error = ""
        if request.method == "POST":
            for key in tuple(form):
                if key in {"loopback", "authorized"}:
                    form[key] = request.form.get(key) == "on"
                else:
                    form[key] = request.form.get(key, str(form[key])).strip()
            try:
                if not form["authorized"]:
                    raise ToolInputError(
                        "Confirm that you are authorized to join or generate multicast traffic on the selected network."
                    )
                result = run_multicast_test(form, interfaces=interfaces)
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid multicast test settings."
            _record_multicast_activity(result, error, form)

        return render_template(
            "tools/multicast.html",
            capability=capability,
            error=error,
            form=form,
            interfaces=interfaces,
            limits={
                "duration": MULTICAST_MAX_DURATION_SECONDS,
                "packet_size_min": MULTICAST_MIN_PACKET_SIZE,
                "packet_size_max": MULTICAST_MAX_PACKET_SIZE,
                "megabits": MULTICAST_MAX_MEGABITS,
                "packets_per_second": MULTICAST_MAX_PACKETS_PER_SECOND,
            },
            result=result,
        )


def _record_multicast_activity(
    result: dict | None,
    error: str,
    form: dict[str, object],
) -> None:
    mode = str(form.get("mode", "listen"))[:20]
    packets_sent = _result_count(result, "packets_sent")
    packets_received = _result_count(result, "packets_received")
    bytes_sent = _result_count(result, "bytes_sent")
    bytes_received = _result_count(result, "bytes_received")
    if result and mode == "path":
        bytes_sent = _result_count(result.get("send"), "bytes_sent")
        bytes_received = _result_count(result.get("receive"), "bytes_received")
    counters = {
        "multicast": {
            "tests": 1,
            "packets_sent": packets_sent,
            "packets_received": packets_received,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
        }
    }
    record_current_activity(
        "Multicast",
        "Ran multicast test",
        "Request failed"
        if error
        else (
            f"{mode} · {packets_received:,} received"
            if mode != "send"
            else f"send · {packets_sent:,} sent"
        ),
        counters=counters,
    )
    annotate_tool_run(
        category="Network tools",
        action_namespace="multicast",
        tool_name="multicast test",
        outcome="failed" if error else str((result or {}).get("status", "completed")),
        details={
            "mode": mode,
            "group scope": str((result or {}).get("group_scope", ""))[:40],
            "membership": str(form.get("membership", ""))[:10],
            "duration seconds": str(form.get("duration", ""))[:10],
            "packets sent": packets_sent,
            "packets received": packets_received,
            "bytes sent": bytes_sent,
            "bytes received": bytes_received,
        },
    )


def _result_count(result: dict | None, key: str) -> int:
    try:
        return max(0, int((result or {}).get(key) or 0))
    except (TypeError, ValueError):
        return 0
