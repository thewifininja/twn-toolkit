from __future__ import annotations

import secrets
import time

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from .activity_context import record_current_activity
from .audit import annotate_tool_run
from .iperf_server import (
    IPERF_SERVER_RESULT_LIMIT,
    IperfServerStore,
)
from .iperf_tools import (
    IPERF_DEFAULT_PORT,
    IPERF_MAX_DURATION_SECONDS,
    IPERF_MAX_PARALLEL_STREAMS,
    IPERF_MAX_UDP_MEGABITS,
    iperf3_capability,
    run_iperf3_client,
)
from .network_tools import ToolInputError
from .investigation_context import record_current_investigation_event
from .ping_investigation import recording_case_id
from .iperf_investigation import (
    finalize_pending_iperf_servers,
    record_iperf_server_started,
)


def register_iperf_routes(tools_bp: Blueprint) -> None:
    def server_store() -> IperfServerStore:
        return IperfServerStore(current_app.instance_path)

    @tools_bp.route("/iperf3", methods=["GET", "POST"])
    def iperf3():
        finalize_pending_iperf_servers(
            current_app.instance_path,
            user_id=str(g.current_user["id"]),
        )
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
        result = None
        journal_event = None
        error = ""
        if request.method == "POST":
            operation_id = f"iperf3-client:{secrets.token_hex(12)}"
            journal_started_at = time.time()
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
            _record_client_activity(result, error, client_form)
            safe_result = _journal_iperf_result(result)
            metric = (safe_result or {}).get("receiver") or (safe_result or {}).get("sender") or {}
            journal_event = record_current_investigation_event(
                operation_id=operation_id,
                event_type="diagnostic.failed" if error else "diagnostic.completed",
                tool_id="tools.iperf3",
                action="iPerf3 client test",
                outcome="failed" if error else "succeeded",
                summary=(
                    f"iPerf3 client test failed: {error}"
                    if error
                    else (
                        f"Ran {safe_result.get('protocol', 'iPerf3')} throughput test to "
                        f"{client_form['host']}: {metric.get('megabits_per_second', 'unknown')} Mbps."
                    )
                ),
                targets={"host": client_form["host"], "port": client_form["port"]},
                parameters={
                    "protocol": client_form["protocol"],
                    "family": client_form["family"],
                    "duration_seconds": client_form["duration_seconds"],
                    "parallel_streams": client_form["parallel_streams"],
                    "bind_address": client_form["bind_address"],
                    "reverse": client_form["reverse"] == "on",
                    "udp_megabits": client_form["udp_megabits"],
                },
                metrics={
                    "transferred_bytes": safe_result.get("transferred_bytes", 0),
                    "sender_mbps": (safe_result.get("sender") or {}).get("megabits_per_second"),
                    "receiver_mbps": (safe_result.get("receiver") or {}).get("megabits_per_second"),
                    "retransmits": (safe_result.get("sender") or {}).get("retransmits"),
                    "lost_packets": (safe_result.get("receiver") or safe_result.get("sender") or {}).get("lost_packets"),
                    "jitter_ms": (safe_result.get("receiver") or safe_result.get("sender") or {}).get("jitter_ms"),
                }
                if safe_result
                else {},
                details={"error": error, "result": safe_result},
                started_at=journal_started_at,
                completed_at=time.time(),
            )

        user_id = str(g.current_user["id"])
        managed_store = server_store()
        active_server = managed_store.active_for_user(user_id)
        latest_server = managed_store.latest_for_user(user_id)
        server_form = {
            "bind_address": str(
                (active_server or {}).get("bind_address") or "0.0.0.0"
            ),
            "port": str(
                (active_server or {}).get("port") or IPERF_DEFAULT_PORT
            ),
        }
        server_results = managed_store.recent_results(user_id)
        return render_template(
            "tools/iperf3.html",
            active_server=active_server,
            capability=iperf3_capability(),
            client_form=client_form,
            error=error,
            limits={
                "duration": IPERF_MAX_DURATION_SECONDS,
                "parallel_streams": IPERF_MAX_PARALLEL_STREAMS,
                "udp_megabits": IPERF_MAX_UDP_MEGABITS,
                "server_history": IPERF_SERVER_RESULT_LIMIT,
            },
            latest_server=latest_server,
            result=result,
            server_form=server_form,
            server_result_revision=managed_store.result_revision(user_id),
            server_results=server_results,
            journal_event=journal_event,
        )

    @tools_bp.post("/iperf3/server/start")
    def start_iperf3_server():
        config = {
            "bind_address": request.form.get(
                "server_bind_address", "0.0.0.0"
            ).strip(),
            "port": request.form.get(
                "server_port", str(IPERF_DEFAULT_PORT)
            ).strip(),
        }
        user_id = str(g.current_user["id"])
        try:
            if request.form.get("server_authorized") != "on":
                raise ToolInputError(
                    "Confirm that you are authorized to expose this "
                    "managed iPerf3 listener."
                )
            managed_store = server_store()
            try:
                investigation_id = recording_case_id(
                    current_app.instance_path, user_id
                )
            except Exception:
                current_app.logger.exception(
                    "Active case context could not be loaded for iPerf3 server"
                )
                investigation_id = ""
            session_id = managed_store.create(
                config,
                created_by=user_id,
                created_by_username=str(g.current_user.get("username", "")),
                investigation_id=investigation_id,
            )
            managed_store.launch(session_id)
            session = managed_store.get(session_id, user_id=user_id)
        except (ToolInputError, TypeError, ValueError) as exc:
            annotate_tool_run(
                category="Network tools",
                action_namespace="iperf3.server",
                tool_name="managed iPerf3 server",
                outcome="failed",
                details={
                    "port": str(config["port"])[:10],
                    "mode": "start",
                },
            )
            flash(str(exc) or "Enter valid iPerf3 server settings.", "error")
            return redirect(url_for("tools.iperf3"))

        annotate_tool_run(
            category="Network tools",
            action_namespace="iperf3.server",
            tool_name="managed iPerf3 server",
            outcome="started",
            details={
                "server id": session_id,
                "port": int((session or {}).get("port") or config["port"]),
                "address family": (
                    "IPv6"
                    if ":" in str((session or {}).get("bind_address") or "")
                    else "IPv4"
                ),
            },
        )
        record_current_activity(
            "Throughput",
            "Started managed iPerf3 server",
            f"Listening on port {(session or {}).get('port', config['port'])}",
        )
        case_recorded = False
        if session and session.get("investigation_id"):
            try:
                case_recorded = bool(
                    record_iperf_server_started(
                        current_app.instance_path, session=session
                    )
                )
            except Exception:
                current_app.logger.exception(
                    "Unable to record the iPerf3 server start in its attached case"
                )
        flash(
            "Managed iPerf3 server started. It will remain available in the "
            "background until you stop it."
            + (" It is attached to the active case." if case_recorded else ""),
            "success",
        )
        return redirect(url_for("tools.iperf3"))

    @tools_bp.post("/iperf3/server/<session_id>/stop")
    def stop_iperf3_server(session_id: str):
        user_id = str(g.current_user["id"])
        wants_json = request.accept_mimetypes.best == "application/json"
        try:
            session = server_store().request_stop(
                session_id,
                user_id=user_id,
            )
        except ToolInputError as exc:
            if wants_json:
                return jsonify({"error": str(exc)}), 400
            flash(str(exc), "error")
        else:
            annotate_tool_run(
                category="Network tools",
                action_namespace="iperf3.server",
                tool_name="managed iPerf3 server",
                outcome="stop requested",
                details={
                    "server id": session_id,
                    "port": session["port"],
                    "tests completed": session["test_count"],
                },
            )
            record_current_activity(
                "Throughput",
                "Stopped managed iPerf3 server",
                f"{session['test_count']} completed test"
                f"{'' if session['test_count'] == 1 else 's'}",
            )
            if wants_json:
                return jsonify(
                    {"session": _public_server_session(session)}
                )
            flash("Managed iPerf3 server is stopping.", "success")
        return redirect(url_for("tools.iperf3"))

    @tools_bp.get("/iperf3/server/<session_id>/status")
    def iperf3_server_status(session_id: str):
        finalize_pending_iperf_servers(
            current_app.instance_path,
            user_id=str(g.current_user["id"]),
            session_id=session_id,
        )
        user_id = str(g.current_user["id"])
        managed_store = server_store()
        session = managed_store.get(session_id, user_id=user_id)
        if not session:
            abort(404)
        results = managed_store.recent_results(user_id)
        return jsonify(
            {
                "session": _public_server_session(session),
                "result_count": len(results),
                "result_revision": managed_store.result_revision(user_id),
                "results_html": render_template(
                    "tools/_iperf_server_results.html",
                    server_results=results,
                ),
            }
        )

    @tools_bp.post("/iperf3/server/results/clear")
    def clear_iperf3_server_results():
        user_id = str(g.current_user["id"])
        removed = server_store().clear_results(user_id)
        annotate_tool_run(
            category="Network tools",
            action_namespace="iperf3.server",
            tool_name="managed iPerf3 server",
            outcome="history cleared",
            details={"results removed": removed},
        )
        flash(
            f"Cleared {removed} retained iPerf3 server result"
            f"{'' if removed == 1 else 's'}.",
            "success",
        )
        return redirect(url_for("tools.iperf3"))


def _record_client_activity(
    result: dict | None,
    error: str,
    form: dict[str, str],
) -> None:
    if error:
        record_current_activity(
            "Throughput",
            "Ran iPerf3 client test",
            "Request failed",
        )
    else:
        summary = _iperf_summary(result or {})
        record_current_activity(
            "Throughput",
            "Ran iPerf3 client test",
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
    annotate_tool_run(
        category="Network tools",
        action_namespace="iperf3.client",
        tool_name="iPerf3 client test",
        outcome="failed" if error else "succeeded",
        details={
            "mode": "client",
            "port": str(form.get("port", ""))[:10],
            "protocol": str(
                (result or {}).get("protocol") or form.get("protocol", "")
            )[:10],
            "transferred bytes": int(
                (result or {}).get("transferred_bytes") or 0
            ),
            "duration seconds": str(
                form.get("duration_seconds", "")
            )[:10],
            "parallel streams": str(
                form.get("parallel_streams", "")
            )[:10],
            "reverse": form.get("reverse") == "on",
        },
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


def _public_server_session(session: dict) -> dict:
    return {
        key: session.get(key)
        for key in (
            "id",
            "status",
            "active",
            "desired_active",
            "bind_address",
            "port",
            "test_count",
            "started_at_display",
            "last_test_at_display",
            "last_error",
            "stop_reason",
            "error",
        )
    }


def _journal_iperf_result(result: dict | None) -> dict:
    if not result:
        return {}
    return {
        key: result.get(key)
        for key in (
            "mode",
            "protocol",
            "direction",
            "version",
            "system_info",
            "connection",
            "sender",
            "receiver",
            "intervals",
            "cpu",
            "transferred_bytes",
            "transferred_display",
        )
    }
