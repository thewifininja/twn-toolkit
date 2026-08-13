from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .investigations import InvestigationError, InvestigationStore
from .iperf_server import IperfServerStore


class IperfInvestigationError(RuntimeError):
    pass


def record_iperf_server_started(
    instance_path: str | Path, *, session: dict[str, Any]
) -> dict[str, Any] | None:
    investigation_id = str(session.get("investigation_id", ""))
    if not investigation_id:
        return None
    created_at = float(session["created_at"])
    return InvestigationStore(instance_path).record_for_case(
        investigation_id=investigation_id,
        user_id=str(session["created_by"]),
        username=str(session.get("created_by_username", "")),
        require_recording=True,
        operation_id=f"iperf-server-start:{session['id']}",
        event_type="iperf.server.started",
        tool_id="tools.iperf3",
        action="iPerf3 server started",
        outcome="info",
        summary=f"Started managed iPerf3 listener on {session['bind_address']}:{session['port']}.",
        targets={"bind_address": session["bind_address"], "port": session["port"]},
        parameters={"session_id": session["id"]},
        metrics={},
        details={},
        started_at=created_at,
        completed_at=created_at,
    )


def finalize_pending_iperf_servers(
    instance_path: str | Path,
    *,
    user_id: str = "",
    investigation_id: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    store = IperfServerStore(instance_path)
    sessions = store.pending_investigation_sessions(
        user_id=user_id,
        investigation_id=investigation_id,
        session_id=session_id,
    )
    finalized: list[str] = []
    failures: list[dict[str, str]] = []
    for session in sessions:
        try:
            _finalize_iperf_server(instance_path, store, session)
        except (InvestigationError, OSError, IperfInvestigationError) as exc:
            failures.append({"session_id": str(session["id"]), "error": str(exc)})
        else:
            finalized.append(str(session["id"]))
    return {"finalized": finalized, "failures": failures}


def stop_and_finalize_case_iperf_servers(
    instance_path: str | Path,
    *,
    investigation_id: str,
    user_id: str,
) -> dict[str, Any]:
    store = IperfServerStore(instance_path)
    active = store.active_for_investigation(investigation_id, user_id=user_id)
    stop_requested = len(active)
    for session in active:
        if session["status"] != "stopping":
            store.request_stop(str(session["id"]), user_id=user_id)
    deadline = time.monotonic() + 12
    while active and time.monotonic() < deadline:
        time.sleep(0.1)
        active = store.active_for_investigation(investigation_id, user_id=user_id)
    if active:
        raise IperfInvestigationError(
            "The case remains open while its attached iPerf3 server is stopping. "
            "Wait a moment, then close the case again."
        )
    result = finalize_pending_iperf_servers(
        instance_path, user_id=user_id, investigation_id=investigation_id
    )
    if result["failures"]:
        first = result["failures"][0]
        raise IperfInvestigationError(
            "The case remains open because iPerf3 server evidence could not be "
            f"retained: {first['error']}"
        )
    return {"stopped": stop_requested, "finalized": len(result["finalized"])}


def _finalize_iperf_server(
    instance_path: str | Path,
    store: IperfServerStore,
    session: dict[str, Any],
) -> None:
    results = [_safe_result(result) for result in store.results_for_session(session["id"])]
    stopped_at = float(session.get("stopped_at") or session.get("updated_at"))
    failed = session.get("status") == "error"
    transferred = sum(int(result.get("transferred_bytes") or 0) for result in results)
    rates = [
        float(result.get("summary_megabits_per_second") or 0)
        for result in results
        if result.get("summary_megabits_per_second") is not None
    ]
    evidence = InvestigationStore(instance_path).add_generated_evidence_event(
        investigation_id=str(session["investigation_id"]),
        user_id=str(session["created_by"]),
        username=str(session.get("created_by_username", "")),
        operation_id=f"iperf-server-final:{session['id']}",
        event_type="iperf.server.failed" if failed else "iperf.server.completed",
        tool_id="tools.iperf3",
        action="iPerf3 server failed" if failed else "iPerf3 server stopped",
        outcome="failed" if failed else "succeeded",
        summary=(
            f"Managed iPerf3 server failed: {session.get('error', '')}"
            if failed
            else f"Stopped managed iPerf3 server after {len(results)} completed test(s)."
        ),
        targets={"bind_address": session["bind_address"], "port": session["port"]},
        parameters={
            "session_id": session["id"],
            "duration_seconds": round(
                max(0, stopped_at - float(session.get("started_at") or session["created_at"])),
                3,
            ),
            "termination": session.get("stop_reason", ""),
        },
        metrics={
            "test_count": len(results),
            "transferred_bytes": transferred,
            "peak_mbps": round(max(rates), 2) if rates else None,
        },
        details={
            "results": results[:50],
            "last_error": session.get("last_error", ""),
            "error": session.get("error", ""),
        },
        started_at=stopped_at,
        completed_at=stopped_at,
        filename=f"iperf3-server-{session['id']}-results.json",
        content_type="application/json",
        content=json.dumps(results, indent=2, ensure_ascii=False).encode("utf-8"),
    )
    if not evidence.get("artifact"):
        raise IperfInvestigationError("iPerf3 server evidence was not retained.")
    store.mark_investigation_finalized(str(session["id"]))


def _safe_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: result.get(key)
        for key in (
            "id", "source_ip", "source_port", "completed_at", "mode",
            "protocol", "direction", "version", "system_info", "connection",
            "sender", "receiver", "intervals", "cpu", "transferred_bytes",
            "transferred_display", "summary_megabits_per_second",
        )
    }
