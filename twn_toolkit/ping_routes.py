from __future__ import annotations

import time

from flask import Blueprint, current_app, jsonify, render_template, request

from .activity_context import increment_current_activity, record_current_activity
from .audit import (
    annotate_audit_event,
    annotate_profile_deleted,
    annotate_profile_saved,
    suppress_audit_event,
)
from .network_tools import (
    ToolInputError,
    parse_ping_targets,
    parse_ping_targets_with_errors,
    ping_engine_capability,
    ping_hosts,
)
from .profiles import PingProfileStore


def register_ping_routes(tools_bp: Blueprint) -> None:
    @tools_bp.get("/ping")
    def ping_tool():
        capability = ping_engine_capability()
        return render_template(
            "tools/ping.html",
            profiles=_ping_profile_store().all(),
            ping_capability=capability,
            ping_target_limit=capability["target_limit"],
        )

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
            timeout = _ping_timeout(payload.get("timeout", 1), capability)
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
            timeout = _ping_timeout(payload.get("timeout", 1), capability)
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


def _ping_profile_store() -> PingProfileStore:
    return PingProfileStore(current_app.instance_path)


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = minimum
    return max(minimum, min(maximum, parsed))


def _ping_timeout(value: object, capability: dict[str, object]) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ToolInputError("Probe timeout must be a number.") from exc
    minimum = 0.1 if capability.get("accelerated") else 1.0
    if not minimum <= timeout <= 10:
        raise ToolInputError(
            f"Probe timeout must be between {minimum:g} and 10 seconds for the "
            f"{capability.get('engine', 'active')} ping engine."
        )
    return timeout


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
