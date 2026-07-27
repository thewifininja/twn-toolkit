from __future__ import annotations

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .iperf_tools import (
    IPERF_DEFAULT_PORT,
    IPERF_MAX_DURATION_SECONDS,
    IPERF_MAX_PARALLEL_STREAMS,
    IPERF_MAX_SERVER_WINDOW_SECONDS,
    IPERF_MAX_UDP_MEGABITS,
    iperf3_capability,
    run_iperf3_client,
    run_iperf3_server,
)
from .network_tools import ToolInputError


def register_iperf_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/iperf3", methods=["GET", "POST"])
    def iperf3():
        client_form = {
            "host": "",
            "port": str(IPERF_DEFAULT_PORT),
            "protocol": "tcp",
            "family": "auto",
            "duration_seconds": "10",
            "parallel_streams": "1",
            "bind_address": "",
            "reverse": "",
            "udp_megabits": "100",
            "authorized": "",
        }
        server_form = {
            "bind_address": "0.0.0.0",
            "port": str(IPERF_DEFAULT_PORT),
            "window_seconds": "90",
            "authorized": "",
        }
        action = "client"
        result = None
        error = ""
        if request.method == "POST":
            action = request.form.get("action", "client").strip().lower()
            if action == "server":
                server_form = {
                    key: request.form.get(f"server_{key}", default).strip()
                    for key, default in server_form.items()
                }
                try:
                    if server_form["authorized"] != "on":
                        raise ToolInputError(
                            "Confirm that you are authorized to expose this "
                            "one-shot iPerf3 listener."
                        )
                    result = run_iperf3_server(
                        {
                            "bind_address": server_form["bind_address"],
                            "port": server_form["port"],
                            "window_seconds": server_form["window_seconds"],
                        }
                    )
                except (ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc) or "Enter valid iPerf3 server settings."
                _record_iperf_activity(action, result, error, server_form)
            else:
                action = "client"
                client_form = {
                    key: request.form.get(f"client_{key}", default).strip()
                    for key, default in client_form.items()
                }
                try:
                    if client_form["authorized"] != "on":
                        raise ToolInputError(
                            "Confirm that you are authorized to test this "
                            "iPerf3 destination."
                        )
                    result = run_iperf3_client(
                        {
                            "host": client_form["host"],
                            "port": client_form["port"],
                            "protocol": client_form["protocol"],
                            "family": client_form["family"],
                            "duration_seconds": client_form["duration_seconds"],
                            "parallel_streams": client_form["parallel_streams"],
                            "bind_address": client_form["bind_address"],
                            "reverse": client_form["reverse"] == "on",
                            "udp_megabits": client_form["udp_megabits"],
                        }
                    )
                except (ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc) or "Enter valid iPerf3 client settings."
                _record_iperf_activity(action, result, error, client_form)
        return render_template(
            "tools/iperf3.html",
            action=action,
            capability=iperf3_capability(),
            client_form=client_form,
            error=error,
            limits={
                "duration": IPERF_MAX_DURATION_SECONDS,
                "parallel_streams": IPERF_MAX_PARALLEL_STREAMS,
                "server_window": IPERF_MAX_SERVER_WINDOW_SECONDS,
                "udp_megabits": IPERF_MAX_UDP_MEGABITS,
            },
            result=result,
            server_form=server_form,
        )


def _record_iperf_activity(
    action: str,
    result: dict | None,
    error: str,
    form: dict[str, str],
) -> None:
    mode_label = "client test" if action == "client" else "server test"
    if error:
        record_current_activity(
            "Throughput",
            f"Ran iPerf3 {mode_label}",
            "Request failed",
        )
    else:
        summary = _iperf_summary(result or {})
        record_current_activity(
            "Throughput",
            f"Ran iPerf3 {mode_label}",
            summary,
            counters={
                "speedtest": {
                    "runs": 1,
                    "bytes_transferred": int(
                        (result or {}).get("transferred_bytes") or 0
                    ),
                }
            },
        )
    details = {
        "mode": action,
        "port": str(form.get("port", ""))[:10],
        "protocol": str((result or {}).get("protocol") or form.get("protocol", ""))[
            :10
        ],
        "transferred bytes": int(
            (result or {}).get("transferred_bytes") or 0
        ),
    }
    if action == "client":
        details.update(
            {
                "duration seconds": str(
                    form.get("duration_seconds", "")
                )[:10],
                "parallel streams": str(
                    form.get("parallel_streams", "")
                )[:10],
                "reverse": form.get("reverse") == "on",
            }
        )
    else:
        details["server window seconds"] = str(
            form.get("window_seconds", "")
        )[:10]
    annotate_tool_run(
        category="Network tools",
        action_namespace=f"iperf3.{action}",
        tool_name=f"iPerf3 {mode_label}",
        outcome="failed" if error else "succeeded",
        details=details,
    )


def _iperf_summary(result: dict) -> str:
    metric = result.get("receiver") or result.get("sender") or {}
    rate = metric.get("megabits_per_second")
    protocol = result.get("protocol") or "iPerf3"
    transferred = result.get("transferred_display") or "0 B"
    return (
        f"{protocol} · {rate} Mbps · {transferred}"
        if rate is not None
        else f"{protocol} · {transferred}"
    )
