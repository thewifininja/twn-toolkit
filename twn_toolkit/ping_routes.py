from __future__ import annotations

import time

from flask import Blueprint, current_app, g, jsonify, render_template, request

from .activity_context import increment_current_activity, record_current_activity
from .audit import (
    annotate_audit_event,
    annotate_profile_deleted,
    annotate_profile_duplicated,
    annotate_profile_saved,
    suppress_audit_event,
)
from .iperf_server import IperfServerStore, public_iperf_live_session
from .network_tools import (
    ToolInputError,
    parse_ping_targets,
    parse_ping_targets_with_errors,
    ping_engine_capability,
    ping_hosts,
    validate_ping_timeout,
)
from .live_tools import LiveToolStore, public_live_session
from .ping_investigation import (
    finalize_pending_ping_sessions,
    record_ping_session_started,
    recording_case_id,
)
from .profiles import PingProfileStore
from .snmp_investigation import finalize_pending_snmp_sessions


def register_ping_routes(tools_bp: Blueprint) -> None:
    @tools_bp.get("/ping")
    def ping_tool():
        capability = ping_engine_capability()
        return render_template(
            "tools/ping.html",
            profiles=_ping_profile_store().all(),
            ping_capability=capability,
            ping_target_limit=capability["target_limit"],
            requested_live_session=str(request.args.get("session", "")).strip()[:80],
        )

    @tools_bp.get("/live-sessions")
    def live_tool_sessions():
        suppress_audit_event()
        user = _current_user()
        _finalize_ping_investigations(user_id=user["id"])
        sessions = [
            session
            for session in _live_tool_store().sessions_for_user(user["id"])
            if _live_session_tool_allowed(session["tool_key"])
        ]
        if _tool_allowed("tools.iperf3"):
            iperf_session = IperfServerStore(
                current_app.instance_path
            ).active_for_user(user["id"])
            if iperf_session:
                sessions.append(iperf_session)
        return jsonify(
            {
                "sessions": [
                    (
                        public_iperf_live_session(session)
                        if session.get("status")
                        else public_live_session(session)
                    )
                    for session in sessions
                ]
            }
        )

    @tools_bp.post("/ping/sessions")
    def start_ping_session():
        payload = request.get_json(silent=True) or {}
        capability = ping_engine_capability()
        try:
            targets = parse_ping_targets(
                str(payload.get("hosts", "")), limit=capability["target_limit"]
            )
            interval = int(payload.get("interval", 2))
            if not 1 <= interval <= 60:
                raise ToolInputError("Interval must be between 1 and 60 seconds.")
            timeout = validate_ping_timeout(payload.get("timeout", 1), capability)
            title = " ".join(str(payload.get("title", "")).strip().split())
            if len(title) > 100:
                raise ToolInputError("Live tool names must be 100 characters or fewer.")
            user = _current_user()
            try:
                investigation_id = recording_case_id(
                    current_app.instance_path, user["id"]
                )
            except Exception:
                current_app.logger.exception(
                    "Active case context could not be loaded for Multi-Ping"
                )
                investigation_id = ""
            session = _live_tool_store().create_ping_session(
                user_id=user["id"],
                username=user["username"],
                title=title or "Multi-Host Ping",
                targets=targets,
                interval=interval,
                timeout=timeout,
                investigation_id=investigation_id,
            )
        except (ToolInputError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        detail = f"{len(targets)} target{'s' if len(targets) != 1 else ''} · every {interval}s"
        record_current_activity(
            "Reachability",
            "Started persistent ping run",
            detail,
            count_action=True,
        )
        annotate_audit_event(
            category="Network tools",
            action="ping.live_session_started",
            summary="Started a persistent Multi-Host Ping session.",
            resource_type="live_tool_session",
            resource_id=session["id"],
            resource_name=session["title"],
            details={
                "target_count": len(targets),
                "targets": targets,
                "interval_seconds": interval,
                "timeout_seconds": timeout,
            },
        )
        case_recorded = False
        if session.get("investigation_id"):
            try:
                case_recorded = bool(
                    record_ping_session_started(
                        current_app.instance_path,
                        session=session,
                        targets=targets,
                        interval=interval,
                        timeout=timeout,
                    )
                )
            except Exception:
                current_app.logger.exception(
                    "Unable to record the Multi-Ping start in its attached case"
                )
        return jsonify(
            {
                "session": public_live_session(session, include_config=True),
                "case_recorded": case_recorded,
            }
        ), 201

    @tools_bp.get("/ping/sessions/<session_id>")
    def ping_session(session_id: str):
        suppress_audit_event()
        session = _live_tool_store().renew_session(
            session_id, user_id=_current_user()["id"]
        )
        if not session or session["tool_key"] != "ping":
            return jsonify({"error": "Live ping session not found."}), 404
        return jsonify({"session": public_live_session(session, include_config=True)})

    @tools_bp.get("/ping/sessions/<session_id>/samples")
    def ping_session_samples(session_id: str):
        suppress_audit_event()
        try:
            after_id = int(request.args.get("after", "0"))
            limit = int(request.args.get("limit", "10000"))
        except ValueError:
            return jsonify({"error": "Sample cursor and limit must be integers."}), 400
        page = _live_tool_store().ping_samples(
            session_id,
            user_id=_current_user()["id"],
            after_id=after_id,
            limit=limit,
        )
        if page is None:
            return jsonify({"error": "Live ping session not found."}), 404
        page["session"] = public_live_session(page["session"])
        return jsonify(page)

    @tools_bp.post("/ping/sessions/<session_id>/targets")
    def update_ping_session_targets(session_id: str):
        payload = request.get_json(silent=True) or {}
        capability = ping_engine_capability()
        try:
            targets = parse_ping_targets(
                str(payload.get("hosts", "")), limit=capability["target_limit"]
            )
            interval = int(payload.get("interval", 2))
            if not 1 <= interval <= 60:
                raise ToolInputError("Interval must be between 1 and 60 seconds.")
            timeout = validate_ping_timeout(payload.get("timeout", 1), capability)
            session = _live_tool_store().update_ping_session(
                session_id,
                user_id=_current_user()["id"],
                targets=targets,
                interval=interval,
                timeout=timeout,
            )
        except (ToolInputError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        if not session:
            return jsonify({"error": "Live ping session not found."}), 404
        annotate_audit_event(
            category="Network tools",
            action="ping.live_session_targets_updated",
            summary="Updated persistent Multi-Host Ping targets.",
            resource_type="live_tool_session",
            resource_id=session["id"],
            resource_name=session["title"],
            details={
                "target_count": len(targets),
                "targets": targets,
                "interval_seconds": interval,
                "timeout_seconds": timeout,
            },
        )
        return jsonify({"session": public_live_session(session, include_config=True)})

    @tools_bp.post("/live-sessions/<session_id>/stop")
    def stop_live_tool_session(session_id: str):
        user = _current_user()
        existing = _live_tool_store().get_session(
            session_id,
            user_id=user["id"],
        )
        if not existing:
            return jsonify({"error": "Live tool session not found."}), 404
        if not _live_session_tool_allowed(existing["tool_key"]):
            return jsonify({"error": "This user cannot stop that live tool."}), 403
        session = _live_tool_store().stop_session(session_id, user_id=user["id"])
        if not session:  # pragma: no cover - ownership was checked above
            return jsonify({"error": "Live tool session not found."}), 404
        if not session.get("_was_running", False):
            suppress_audit_event()
            if session["tool_key"] == "ping":
                _finalize_ping_investigations(
                    user_id=user["id"], session_id=str(session["id"])
                )
            elif session["tool_key"] == "snmp_interface":
                _finalize_snmp_investigations(
                    user_id=user["id"], session_id=str(session["id"])
                )
            return jsonify({"session": public_live_session(session)})
        if session["tool_key"] == "snmp_interface":
            detail = (
                f"{session['target_count']} interface"
                f"{'s' if session['target_count'] != 1 else ''} · "
                f"{session['probes_sent']} polls"
            )
            record_current_activity(
                "Infrastructure",
                "Stopped persistent SNMP bandwidth monitor",
                detail,
                count_action=False,
            )
            annotate_audit_event(
                category="Infrastructure",
                action="snmp.live_interface_session_stopped",
                summary="Stopped a persistent SNMP bandwidth monitor.",
                resource_type="live_tool_session",
                resource_id=session["id"],
                resource_name=session["title"],
                details={
                    "interface_count": session["target_count"],
                    "polls_sent": session["probes_sent"],
                    "successful_polls": session["replies_received"],
                },
            )
            _finalize_snmp_investigations(
                user_id=user["id"], session_id=str(session["id"])
            )
        else:
            detail = (
                f"{session['target_count']} target"
                f"{'s' if session['target_count'] != 1 else ''} · "
                f"{session['probes_sent']} probes"
            )
            record_current_activity(
                "Reachability",
                "Stopped persistent ping run",
                detail,
                count_action=False,
            )
            annotate_audit_event(
                category="Network tools",
                action="ping.live_session_stopped",
                summary="Stopped a persistent Multi-Host Ping session.",
                resource_type="live_tool_session",
                resource_id=session["id"],
                resource_name=session["title"],
                details={
                    "target_count": session["target_count"],
                    "probes_sent": session["probes_sent"],
                    "replies_received": session["replies_received"],
                },
            )
            _finalize_ping_investigations(
                user_id=user["id"], session_id=str(session["id"])
            )
        return jsonify({"session": public_live_session(session)})

    @tools_bp.post("/live-sessions/<session_id>/rename")
    def rename_live_tool_session(session_id: str):
        payload = request.get_json(silent=True) or {}
        title = " ".join(str(payload.get("title", "")).strip().split())
        if not title:
            return jsonify({"error": "Live tool names cannot be blank."}), 400
        if len(title) > 100:
            return jsonify(
                {"error": "Live tool names must be 100 characters or fewer."}
            ), 400
        existing = _live_tool_store().get_session(
            session_id,
            user_id=_current_user()["id"],
        )
        if not existing:
            return jsonify({"error": "Live tool session not found."}), 404
        if not _live_session_tool_allowed(existing["tool_key"]):
            return jsonify({"error": "This user cannot rename that live tool."}), 403
        session = _live_tool_store().rename_session(
            session_id,
            user_id=_current_user()["id"],
            title=title,
        )
        if not session:
            return jsonify({"error": "Live tool session not found."}), 404
        if session.get("_renamed", False):
            annotate_audit_event(
                category="Network tools",
                action="live_tool.session_renamed",
                summary="Renamed a live tool session.",
                resource_type="live_tool_session",
                resource_id=session["id"],
                resource_name=session["title"],
                details={
                    "previous_name": session["_previous_title"],
                    "new_name": session["title"],
                    "tool": session["tool_key"],
                },
            )
        else:
            suppress_audit_event()
        return jsonify({"session": public_live_session(session)})

    @tools_bp.post("/ping/run")
    def ping_run():
        suppress_audit_event()
        payload = request.get_json(silent=True) or {}
        capability = ping_engine_capability()
        started = time.monotonic()
        try:
            targets = parse_ping_targets(
                str(payload.get("hosts", "")), limit=capability["target_limit"]
            )
            timeout = validate_ping_timeout(payload.get("timeout", 1), capability)
            results = ping_hosts(
                [target["host"] for target in targets], timeout=timeout
            )
        except (ToolInputError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        for target, result in zip(targets, results):
            result["label"] = target["label"]
        return jsonify(
            {
                "results": results,
                "round": {
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                    "engine": capability["engine"],
                    "timeout": timeout,
                },
            }
        )

    @tools_bp.post("/ping/validate")
    def ping_validate_targets():
        suppress_audit_event()
        payload = request.get_json(silent=True) or {}
        capability = ping_engine_capability()
        try:
            targets, invalid = parse_ping_targets_with_errors(
                str(payload.get("hosts", "")), limit=capability["target_limit"]
            )
        except ToolInputError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"targets": targets, "invalid": invalid})

    @tools_bp.post("/ping/activity")
    def ping_activity():
        payload = request.get_json(silent=True) or {}
        event = str(payload.get("event", "checkpoint")).strip().lower()
        run_id = str(payload.get("run_id", ""))[:80]
        probes_sent = _bounded_int(payload.get("probes_sent", 0), 0, 100_000)
        replies_received = _bounded_int(payload.get("replies_received", 0), 0, probes_sent)
        targets = _bounded_int(payload.get("targets", 0), 0, 250)
        counters = {"ping": {}}
        if probes_sent:
            counters["ping"]["probes_sent"] = probes_sent
        if replies_received:
            counters["ping"]["replies_received"] = replies_received
        if event == "start":
            target_hosts = _audit_ping_targets(payload.get("target_hosts"))
            counters["ping"]["sessions_started"] = 1
            if targets:
                counters["ping"]["targets_started"] = targets
            record_current_activity(
                "Reachability",
                "Started ping run",
                f"{targets} target{'s' if targets != 1 else ''}",
                counters=counters,
                count_action=True,
            )
            annotate_audit_event(
                category="Network tools",
                action="ping.session_started",
                summary="Started Multi-Host Ping.",
                resource_type="ping_session",
                resource_id=run_id,
                resource_name="Multi-Host Ping",
                details={
                    "target_count": targets,
                    "targets": target_hosts,
                },
            )
        elif event == "final":
            if probes_sent or replies_received:
                record_current_activity(
                    "Reachability",
                    "Stopped ping run",
                    _ping_activity_detail(probes_sent, replies_received, run_id),
                    counters=counters,
                    count_action=False,
                )
            else:
                record_current_activity(
                    "Reachability",
                    "Stopped ping run",
                    "No new probes since the last checkpoint.",
                    count_action=False,
                )
            annotate_audit_event(
                category="Network tools",
                action="ping.session_stopped",
                summary="Stopped Multi-Host Ping.",
                resource_type="ping_session",
                resource_id=run_id,
                resource_name="Multi-Host Ping",
            )
        else:
            for counter, amount in counters["ping"].items():
                increment_current_activity("ping", counter, amount)
            suppress_audit_event()
        return jsonify({"ok": True})

    @tools_bp.post("/ping/profiles")
    def save_ping_profile():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name", "")).strip()
        original_name = str(payload.get("original_name", "")).strip()
        if not name:
            return jsonify({"error": "Enter a profile name."}), 400
        if len(name) > 100:
            return jsonify({"error": "Profile names must be 100 characters or fewer."}), 400
        capability = ping_engine_capability()
        try:
            targets = parse_ping_targets(
                str(payload.get("hosts", "")), limit=capability["target_limit"]
            )
            interval = int(payload.get("interval", 2))
            if not 1 <= interval <= 60:
                raise ToolInputError("Interval must be between 1 and 60 seconds.")
            timeout = validate_ping_timeout(payload.get("timeout", 1), capability)
        except (ToolInputError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc) or "Enter a valid interval."}), 400

        profile = {
            "name": name,
            "targets": targets,
            "interval": interval,
            "timeout": timeout,
        }
        store = _ping_profile_store()
        before = store.get(original_name or name)
        store.upsert(profile, original_name=original_name)
        annotate_profile_saved(
            category="Network tools",
            action_namespace="ping",
            profile_type="Ping profile",
            before=before,
            after=profile,
        )
        return jsonify({"profile": profile})

    @tools_bp.post("/ping/profiles/delete")
    def delete_ping_profile():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name", "")).strip()
        if not name:
            return jsonify({"error": "Select a profile to delete."}), 400
        store = _ping_profile_store()
        profile = store.get(name)
        if not profile or not store.delete(name):
            return jsonify({"error": "Profile not found."}), 404
        annotate_profile_deleted(
            category="Network tools",
            action_namespace="ping",
            profile_type="Ping profile",
            profile=profile,
        )
        return jsonify({"deleted": name})

    @tools_bp.post("/ping/profiles/duplicate")
    def duplicate_ping_profile():
        name = request.form.get("name", "").strip()
        store = _ping_profile_store()
        source = store.get(name)
        if not source:
            return jsonify({"error": "Profile not found."}), 404
        copied = store.duplicate(name)
        annotate_profile_duplicated(
            category="Network tools", action_namespace="ping",
            profile_type="Ping profile", source=source, copied=copied,
        )
        return jsonify({"profile": {"name": copied["name"]}})


def _ping_profile_store() -> PingProfileStore:
    return PingProfileStore(current_app.instance_path)


def _live_tool_store() -> LiveToolStore:
    return LiveToolStore(current_app.instance_path)


def _finalize_ping_investigations(*, user_id: str, session_id: str = "") -> None:
    try:
        result = finalize_pending_ping_sessions(
            current_app.instance_path,
            user_id=user_id,
            session_id=session_id,
        )
    except Exception:
        current_app.logger.exception("Unable to finalize Multi-Ping case evidence")
        return
    for failure in result["failures"]:
        current_app.logger.warning(
            "Unable to finalize Multi-Ping session %s: %s",
            failure["session_id"],
            failure["error"],
        )


def _finalize_snmp_investigations(*, user_id: str, session_id: str = "") -> None:
    try:
        result = finalize_pending_snmp_sessions(
            current_app.instance_path,
            user_id=user_id,
            session_id=session_id,
        )
    except Exception:
        current_app.logger.exception("Unable to finalize SNMP monitor case evidence")
        return
    for failure in result["failures"]:
        current_app.logger.warning(
            "Unable to finalize SNMP monitor session %s: %s",
            failure["session_id"],
            failure["error"],
        )


def _current_user() -> dict[str, str]:
    user = getattr(g, "current_user", {}) or {}
    return {
        "id": str(user.get("id", "")),
        "username": str(user.get("username", "")),
    }


def _tool_allowed(tool_id: str) -> bool:
    user = getattr(g, "current_user", {}) or {}
    if user.get("is_admin"):
        return True
    return tool_id in (getattr(g, "allowed_tool_ids", None) or set())


def _live_session_tool_allowed(tool_key: str) -> bool:
    owner = {
        "ping": "tools.ping",
        "snmp_interface": "tools.snmp_test",
    }.get(str(tool_key), "")
    return bool(owner and _tool_allowed(owner))


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = minimum
    return max(minimum, min(maximum, parsed))


def _audit_ping_targets(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    targets = []
    for item in value[:250]:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host", "")).strip()[:255]
        label = str(item.get("label", "")).strip()[:100]
        if host:
            targets.append({"host": host, "label": label})
    return targets


def _ping_activity_detail(probes_sent: int, replies_received: int, run_id: str) -> str:
    loss = probes_sent - replies_received
    detail = f"{probes_sent} probes, {replies_received} replies, {loss} lost"
    if run_id:
        detail = f"{detail} · run {run_id}"
    return detail
