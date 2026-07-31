from __future__ import annotations

import json
import queue
import threading

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
    stream_with_context,
)

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .multicast_tools import (
    MULTICAST_MAX_DURATION_SECONDS,
    MULTICAST_MAX_MEGABITS,
    MULTICAST_MAX_PACKETS_PER_SECOND,
    MULTICAST_MAX_PACKET_SIZE,
    MULTICAST_MIN_PACKET_SIZE,
    MulticastTestCancelled,
    multicast_capability,
    normalize_multicast_config,
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

    @tools_bp.post("/multicast/live")
    def multicast_live():
        payload = request.get_json(silent=True) or {}
        capability = multicast_capability()
        interfaces = capability["interfaces"]
        try:
            if not _checked(payload.get("authorized")):
                raise ToolInputError(
                    "Confirm that you are authorized to join or generate multicast traffic on the selected network."
                )
            if not capability["available"]:
                raise ToolInputError(capability["detail"])
            normalized = normalize_multicast_config(payload, interfaces=interfaces)
        except (ToolInputError, TypeError, ValueError) as exc:
            error = str(exc) or "Enter valid multicast test settings."
            _record_multicast_activity(None, error, payload)
            return jsonify({"error": error}), 400

        annotate_tool_run(
            category="Network tools",
            action_namespace="multicast.stream",
            tool_name="live multicast test",
            outcome="started",
            details={
                "mode": normalized["mode"],
                "group scope": normalized["group_scope"],
                "membership": normalized["membership"],
                "duration seconds": normalized["duration"],
            },
        )
        logger = current_app.logger

        @stream_with_context
        def generate():
            events: queue.Queue[dict | None] = queue.Queue()
            cancelled = threading.Event()

            def worker() -> None:
                try:
                    result = run_multicast_test(
                        payload,
                        interfaces=interfaces,
                        progress=events.put,
                        cancelled=cancelled,
                    )
                except MulticastTestCancelled:
                    events.put({"type": "cancelled"})
                except (ToolInputError, TypeError, ValueError) as exc:
                    events.put(
                        {
                            "type": "error",
                            "error": str(exc) or "The multicast test failed.",
                        }
                    )
                except Exception:
                    logger.exception("Live multicast test failed unexpectedly.")
                    events.put(
                        {
                            "type": "error",
                            "error": "The multicast test stopped unexpectedly.",
                        }
                    )
                else:
                    events.put({"type": "complete", "result": result})
                finally:
                    events.put(None)

            thread = threading.Thread(
                target=worker,
                name="twn-multicast-live",
                daemon=True,
            )
            thread.start()
            try:
                while True:
                    event = events.get()
                    if event is None:
                        break
                    if event["type"] == "complete":
                        result = event["result"]
                        _record_multicast_activity(result, "", payload)
                        event["html"] = _render_multicast_page(
                            capability=capability,
                            form=payload,
                            result=result,
                        )
                    elif event["type"] == "error":
                        _record_multicast_activity(
                            None,
                            str(event.get("error", "")),
                            payload,
                        )
                    yield json.dumps(event, separators=(",", ":")) + "\n"
            finally:
                cancelled.set()
                thread.join(timeout=0.5)

        response = Response(generate(), mimetype="application/x-ndjson")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Accel-Buffering"] = "no"
        return response


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


def _checked(value: object) -> bool:
    return value is True or str(value).strip().lower() in {"1", "on", "true", "yes"}


def _render_multicast_page(
    *,
    capability: dict,
    form: dict,
    result: dict,
) -> str:
    return render_template(
        "tools/multicast.html",
        capability=capability,
        error="",
        form={
            **form,
            "authorized": _checked(form.get("authorized")),
            "loopback": _checked(form.get("loopback")),
        },
        interfaces=capability["interfaces"],
        limits={
            "duration": MULTICAST_MAX_DURATION_SECONDS,
            "packet_size_min": MULTICAST_MIN_PACKET_SIZE,
            "packet_size_max": MULTICAST_MAX_PACKET_SIZE,
            "megabits": MULTICAST_MAX_MEGABITS,
            "packets_per_second": MULTICAST_MAX_PACKETS_PER_SECOND,
        },
        result=result,
    )
