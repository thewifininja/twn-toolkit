from __future__ import annotations

import json
import secrets
import time

from flask import Blueprint, render_template, request

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .diagnostic_tools import receive_syslog, send_syslog
from .network_tools import ToolInputError
from .investigation_context import (
    add_current_investigation_generated_evidence_event,
    record_current_investigation_event,
)


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
        journal_event = None
        error = ""
        if request.method == "POST":
            operation_id = f"syslog:{secrets.token_hex(12)}"
            journal_started_at = time.time()
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
            annotate_tool_run(
                category="Network tools",
                action_namespace=f"syslog.{action}",
                tool_name=f"syslog {action}",
                outcome="failed" if error else "succeeded",
                details={
                    "protocol": (
                        send_form["protocol"] if action == "send" else receive_form["protocol"]
                    ),
                    "message count": 1 if send_result else len(messages or []),
                },
            )
            if error:
                journal_event = record_current_investigation_event(
                    operation_id=operation_id,
                    event_type="diagnostic.failed",
                    tool_id="tools.syslog_receiver",
                    action=f"Syslog {action}",
                    outcome="failed",
                    summary=f"Syslog {action} failed: {error}",
                    targets={
                        "host": send_form["host"] if action == "send" else receive_form["bind_address"],
                        "port": send_form["port"] if action == "send" else receive_form["port"],
                    },
                    parameters={
                        "protocol": send_form["protocol"] if action == "send" else receive_form["protocol"]
                    },
                    metrics={},
                    details={"error": error},
                    started_at=journal_started_at,
                    completed_at=time.time(),
                )
            else:
                retained = messages if action == "receive" else [send_result]
                generated = add_current_investigation_generated_evidence_event(
                    operation_id=operation_id,
                    event_type="diagnostic.completed" if action == "receive" else "action.completed",
                    tool_id="tools.syslog_receiver",
                    action=f"Syslog {action}",
                    outcome="succeeded",
                    summary=(
                        f"Listened for syslog on {receive_form['bind_address']}:{receive_form['port']}: received {len(messages or [])} message(s)."
                        if action == "receive"
                        else f"Sent one syslog message to {send_result['host']}:{send_result['port']}."
                    ),
                    targets={
                        "host": send_form["host"] if action == "send" else receive_form["bind_address"],
                        "port": send_form["port"] if action == "send" else receive_form["port"],
                    },
                    parameters=(
                        {
                            "mode": "send",
                            "protocol": send_form["protocol"],
                            "facility": send_form["facility"],
                            "severity": send_form["severity"],
                            "hostname": send_form["hostname"],
                            "app_name": send_form["app_name"],
                        }
                        if action == "send"
                        else {
                            "mode": "receive",
                            "protocol": receive_form["protocol"],
                            "duration_seconds": receive_form["duration"],
                            "maximum_messages": receive_form["max_messages"],
                        }
                    ),
                    metrics={
                        "message_count": 1 if action == "send" else len(messages or []),
                        "byte_count": (
                            int((send_result or {}).get("bytes") or 0)
                            if action == "send"
                            else sum(int(message.get("bytes") or 0) for message in messages or [])
                        ),
                    },
                    details={
                        "sources": _syslog_source_summaries(messages or [])
                        if action == "receive"
                        else [],
                    },
                    started_at=journal_started_at,
                    completed_at=time.time(),
                    filename=f"syslog-{action}-{operation_id.rsplit(':', 1)[-1]}.json",
                    content_type="application/json",
                    content=json.dumps(retained, indent=2, ensure_ascii=False).encode("utf-8"),
                )
                journal_event = generated["event"] if generated else None
        return render_template(
            "tools/syslog_receiver.html",
            receive_form=receive_form,
            send_form=send_form,
            messages=messages,
            send_result=send_result,
            error=error,
            journal_event=journal_event,
        )


def _syslog_source_summaries(messages: list[dict]) -> list[dict]:
    counts: dict[tuple[str, int], int] = {}
    for message in messages:
        key = (str(message.get("source", "")), int(message.get("source_port") or 0))
        counts[key] = counts.get(key, 0) + 1
    return [
        {"source": source, "port": port, "messages": count}
        for (source, port), count in sorted(counts.items())
    ]
