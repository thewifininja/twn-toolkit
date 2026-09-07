"""Finite, read-only FortiGate wireless history and durable attribution."""
from __future__ import annotations

import json
import sys
import time

from .diagnostic_policy import MAX_RESULT_ROWS
from .fortigate import FortiGateClient
from .fortiap_history import LocalFortiGateWirelessHistorySource, normalize_client_mac, wireless_client_history

TOOL = "wireless_history"
TOOL_ID = "fortigate.wireless_client_history"
TIMELINE_FIELDS = ("first_time", "last_time", "ap", "event", "ssid", "radio", "channel", "ip", "details")
LIVE_FIELDS = ("host", "ap", "ssid", "radio", "channel", "ip", "signal")


def prepare_history_config(profile, form):
    if not profile:
        raise ValueError("Select a valid FortiGate profile.")
    mac = normalize_client_mac(form.get("mac", ""))
    hours = int(form.get("hours", "24"))
    if not 1 <= hours <= 168:
        raise ValueError("Choose a time window from 1 hour to 7 days.")
    vdom = form.get("vdom", "").strip() or profile.get("default_vdom", "root")
    if len(vdom) > 256:
        raise ValueError("VDOM must be no longer than 256 characters.")
    return {"profile": profile, "form": {"profile": profile["name"], "mac": mac, "hours": hours, "vdom": vdom}}


def bounded_result(result, api_key):
    """Store display fields only; never serialize raw vendor events/datetimes."""
    clipped = False

    def text(value, limit=512):
        nonlocal clipped
        value = str(value or "")
        if api_key:
            value = value.replace(api_key, "[redacted]")
        clipped |= len(value) > limit
        return value[:limit]

    rows = [{**{key: text(item.get(key), 2000 if key == "details" else 512) for key in TIMELINE_FIELDS},
             "event_count": item.get("event_count", 0)} for item in result.get("timeline", [])]
    live = result.get("live_clients", [])
    summary = {key: result.get(key, 0) for key in ("hours", "log_row_count", "raw_event_count", "omitted_unknown_ap_count")}
    summary.update({key: text(result.get(key)) for key in ("mac", "vdom", "source", "log_error", "live_error")})
    summary["live_clients"] = [{key: text(item.get(key)) for key in LIVE_FIELDS} for item in live[:100]]
    summary.update(transition_count=len(rows), live_client_count=len(live), live_clients_omitted=max(0, len(live) - 100), fields_clipped=clipped)
    return rows, summary


def execute_history(store, job, config):
    prepared = prepare_history_config(config["profile"], config["form"])
    form = prepared["form"]
    client = FortiGateClient.from_profile(prepared["profile"])
    with client.pooled() as pooled:
        result = wireless_client_history(LocalFortiGateWirelessHistorySource(pooled), form["mac"], form["vdom"], form["hours"])
    if len(result.get("timeline", [])) > MAX_RESULT_ROWS:
        error = f"Wireless history exceeds {MAX_RESULT_ROWS:,} AP transitions. Choose a shorter time window. No partial timeline was retained."
        if store.abort(job["id"], job["token"], "failed", error):
            record_history_outcome(store, job, "failed", error, config=config)
        return
    rows, result = bounded_result(result, client.api_key)
    errors = sum(bool(result[key]) for key in ("log_error", "live_error"))
    outcome = "failed" if errors == 2 else "incomplete" if errors else "succeeded"
    summary = {"result": result, "outcome": outcome}
    try:
        finished = store.finish(job["id"], job["token"], rows, summary)
    except ValueError:
        error = "Wireless history exceeds the diagnostic result storage limit. Choose a shorter time window. No partial timeline was retained."
        if store.abort(job["id"], job["token"], "failed", error):
            record_history_outcome(store, job, "failed", error, config=config)
        return
    if finished:
        record_history_outcome(store, job, outcome, "", config=config, rows=rows, summary=summary)


def record_history_outcome(store, job, state, error, *, config=None, rows=None, summary=None):
    from .activity import ActivityStore
    from .audit import AuditStore
    from .investigations import InvestigationStore

    try:
        if config is None:
            config = job["config"]
            if isinstance(config, str):
                config = json.loads(store.cipher.open(config, job["id"] + ":diagnostic-config"))
        identity = {"user_id": job["user_id"], "username": config["username"]}
        form = config["form"]
        result = (summary or {}).get("result", {})
        metrics = {"matching_events": result.get("raw_event_count", 0), "AP_transitions": len(rows or []),
                   "live_clients": result.get("live_client_count", 0)}
        description = (f"Searched {form['hours']} hour(s) of wireless history for {form['mac']}: "
                       f"{metrics['matching_events']} matching event(s) across {metrics['AP_transitions']} AP transition(s). "
                       f"Outcome: {state}." if summary else "Wireless client history " + state + ": " + error)
        if summary:
            try:
                ActivityStore(str(store.instance)).record_event("Fortinet", "Loaded wireless client history",
                    f"{form['mac']} via {form['profile']} ({form['hours']}h): {state}",
                    counters={"fortinet": {"api_calls": 1, "failures": int(state != "succeeded")}}, count_action=True, **identity)
            except Exception as exc:
                print(f"Wireless history activity recording failed: {type(exc).__name__}", file=sys.stderr)
        try:
            AuditStore(str(store.instance)).record(**identity, method="WORKER", endpoint="fortiap_client_history",
                path="/fortigate/fortiap/client-history", status_code=200, category="Fortinet",
                action="wireless_history." + state, summary=description, resource_id=job["id"],
                details={"operation_id": job["id"], "outcome": state, **metrics})
        except Exception as exc:
            print(f"Wireless history audit recording failed: {type(exc).__name__}", file=sys.stderr)
        if not config.get("investigation_id"):
            return
        # The case keeps its existing bounded collapsed-path projection.
        details = {"error": error}
        if summary:
            details["result"] = {**result, "timeline": (rows or [])[:500],
                "ap_path": [row["ap"] for row in (rows or [])[:500]],
                "timeline_omitted": max(0, len(rows or []) - 500)}
        event = InvestigationStore(str(store.instance)).record_for_case(
            investigation_id=config["investigation_id"], **identity, operation_id="fortigate-wireless-history:" + job["id"],
            event_type="diagnostic.completed" if summary else "diagnostic." + state,
            tool_id=TOOL_ID, action="Wireless client history", outcome="incomplete" if state == "unknown" else state,
            summary=description, targets={"client_mac": form["mac"]},
            parameters={"profile": form["profile"], "VDOM": form["vdom"], "hours": form["hours"]},
            metrics=metrics, details=details, started_at=job.get("started") or job["created"], completed_at=time.time())
        if summary is not None:
            saved = {**summary, "journal_event": {"id": event["id"], "investigation_id": event["investigation_id"]}}
            sealed = store.cipher.seal(json.dumps(saved), job["id"] + ":diagnostic-summary")
            with store.connect(write=True) as db:
                db.execute("UPDATE diagnostic_jobs SET summary=? WHERE id=? AND state='succeeded'", (sealed, job["id"]))
    except Exception as exc:
        # Attribution failures must never cause appliance requests to be replayed.
        print(f"Wireless history outcome recording failed: {type(exc).__name__}", file=sys.stderr)
