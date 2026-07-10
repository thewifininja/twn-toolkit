from __future__ import annotations

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .diagnostic_tools import receive_syslog, send_syslog
from .network_tools import ToolInputError


def register_syslog_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/syslog-receiver", methods=["GET", "POST"])
    def syslog_receiver():
        receive_form = {
            "protocol": "udp",
            "bind_address": "0.0.0.0",
            "port": "5514",
            "duration": "10",
            "max_messages": "100",
        }
        send_form = {
            "protocol": "udp",
            "host": "",
            "port": "514",
            "facility": "16",
            "severity": "6",
            "hostname": "twn-toolkit",
            "app_name": "twn-toolkit",
            "message": "",
            "timeout": "3",
        }
        messages = None
        send_result = None
        error = ""
        if request.method == "POST":
            action = request.form.get("action", "receive")
            if action == "send":
                send_form = {
                    key: request.form.get(f"send_{key}", default).strip()
                    for key, default in send_form.items()
                }
                try:
                    send_result = send_syslog(
                        send_form["protocol"],
                        send_form["host"],
                        int(send_form["port"]),
                        facility=int(send_form["facility"]),
                        severity=int(send_form["severity"]),
                        hostname=send_form["hostname"],
                        app_name=send_form["app_name"],
                        message=send_form["message"],
                        timeout=float(send_form["timeout"]),
                    )
                except (ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc) or "Enter valid syslog sender settings."
                    record_current_activity("Logging", "Sent syslog message", "Request failed")
                else:
                    record_current_activity(
                        "Logging",
                        "Sent syslog message",
                        f"{send_result['protocol']} to {send_result['host']}:{send_result['port']}",
                        counters={"syslog": {"messages": 1}},
                    )
            else:
                receive_form = {
                    key: request.form.get(key, default).strip()
                    for key, default in receive_form.items()
                }
                try:
                    messages = receive_syslog(
                        receive_form["protocol"],
                        receive_form["bind_address"],
                        int(receive_form["port"]),
                        duration=float(receive_form["duration"]),
                        max_messages=int(receive_form["max_messages"]),
                    )
                except (ToolInputError, TypeError, ValueError) as exc:
                    error = str(exc) or "Enter valid syslog receiver settings."
                    record_current_activity("Logging", "Listened for syslog", "Request failed")
                else:
                    record_current_activity(
                        "Logging",
                        "Listened for syslog",
                        f"Received {len(messages)} message(s)",
                        counters={"syslog": {"messages": len(messages)}},
                    )
        return render_template(
            "tools/syslog_receiver.html",
            receive_form=receive_form,
            send_form=send_form,
            messages=messages,
            send_result=send_result,
            error=error,
        )
