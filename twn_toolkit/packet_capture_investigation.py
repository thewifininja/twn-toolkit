from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .investigations import InvestigationError, InvestigationStore
from .packet_capture import PacketCaptureStore


class PacketCaptureInvestigationError(RuntimeError):
    pass


def record_packet_capture_started(
    instance_path: str | Path, *, capture: dict[str, Any]
) -> dict[str, Any] | None:
    investigation_id = str(capture.get("investigation_id", ""))
    if not investigation_id:
        return None
    created_at = float(capture["created_at"])
    return InvestigationStore(instance_path).record_for_case(
        investigation_id=investigation_id,
        user_id=str(capture.get("created_by", "")),
        username=str(capture.get("created_by_username", "")),
        require_recording=True,
        operation_id=f"packet-capture-start:{capture['id']}",
        event_type="packet_capture.started",
        tool_id="tools.packet_capture",
        action="Packet capture started",
        outcome="info",
        summary=f"Started packet capture on {capture['interface']}.",
        targets={"interface": capture["interface"]},
        parameters=_capture_parameters(capture),
        metrics={},
        details={},
        started_at=created_at,
        completed_at=created_at,
    )


def finalize_pending_packet_captures(
    instance_path: str | Path,
    *,
    user_id: str = "",
    investigation_id: str = "",
    capture_id: str = "",
) -> dict[str, Any]:
    capture_store = PacketCaptureStore(instance_path)
    captures = capture_store.pending_investigation_captures(
        user_id=user_id,
        investigation_id=investigation_id,
        capture_id=capture_id,
    )
    finalized: list[str] = []
    failures: list[dict[str, str]] = []
    for capture in captures:
        try:
            _finalize_packet_capture(instance_path, capture_store, capture)
        except (InvestigationError, OSError, PacketCaptureInvestigationError) as exc:
            failures.append({"capture_id": str(capture["id"]), "error": str(exc)})
        else:
            finalized.append(str(capture["id"]))
    return {"finalized": finalized, "failures": failures}


def stop_and_finalize_case_packet_captures(
    instance_path: str | Path,
    *,
    investigation_id: str,
    user_id: str,
) -> dict[str, Any]:
    capture_store = PacketCaptureStore(instance_path)
    active = capture_store.active_for_investigation(
        investigation_id, user_id=user_id
    )
    stop_requested = len(active)
    for capture in active:
        if capture["status"] != "stopping":
            capture_store.request_stop(str(capture["id"]))
    deadline = time.monotonic() + 12
    while active and time.monotonic() < deadline:
        time.sleep(0.1)
        active = capture_store.active_for_investigation(
            investigation_id, user_id=user_id
        )
    if active:
        raise PacketCaptureInvestigationError(
            "The case remains open while its attached packet capture is stopping. "
            "Wait a moment, then close the case again."
        )
    result = finalize_pending_packet_captures(
        instance_path,
        user_id=user_id,
        investigation_id=investigation_id,
    )
    if result["failures"]:
        first = result["failures"][0]
        raise PacketCaptureInvestigationError(
            "The case remains open because packet capture evidence could not be "
            f"retained: {first['error']}"
        )
    return {
        "stopped": stop_requested,
        "finalized": len(result["finalized"]),
    }


def _finalize_packet_capture(
    instance_path: str | Path,
    capture_store: PacketCaptureStore,
    capture: dict[str, Any],
) -> None:
    finished_at = float(capture.get("finished_at") or capture.get("updated_at"))
    error = str(capture.get("error", ""))
    status = str(capture.get("status", ""))
    outcome = "failed" if status == "error" else "succeeded"
    summary = (
        f"Packet capture failed on {capture['interface']}: {error}"
        if status == "error"
        else (
            f"Packet capture on {capture['interface']} retained "
            f"{capture['packet_count']} packet(s) in {capture['size_display']}."
        )
    )
    event = {
        "investigation_id": str(capture["investigation_id"]),
        "user_id": str(capture["created_by"]),
        "username": str(capture.get("created_by_username", "")),
        "operation_id": f"packet-capture-final:{capture['id']}",
        "event_type": "packet_capture.failed" if status == "error" else "packet_capture.completed",
        "tool_id": "tools.packet_capture",
        "action": "Packet capture failed" if status == "error" else "Packet capture completed",
        "outcome": outcome,
        "summary": summary,
        "targets": {"interface": capture["interface"]},
        "parameters": _capture_parameters(capture),
        "metrics": {
            "packet_count": int(capture.get("packet_count") or 0),
            "size_bytes": int(capture.get("size_bytes") or 0),
            "elapsed_seconds": capture.get("elapsed_seconds"),
        },
        "details": {
            "status": status,
            "termination_reason": capture.get("termination_reason", ""),
            "error": error,
        },
        "started_at": finished_at,
        "completed_at": finished_at,
    }
    store = InvestigationStore(instance_path)
    if capture.get("downloadable"):
        source = capture_store.output_file(capture)
        if not source.is_file():
            raise PacketCaptureInvestigationError(
                "The completed packet capture file is missing."
            )
        with source.open("rb") as stream:
            evidence = store.add_generated_evidence_event(
                **event,
                filename=_capture_filename(capture),
                content_type="application/vnd.tcpdump.pcap",
                stream=stream,
                max_bytes=max(1, int(capture.get("max_size_mib") or 1))
                * 1024
                * 1024,
            )
        if not evidence.get("artifact"):
            raise PacketCaptureInvestigationError(
                "Packet capture evidence was not retained."
            )
    else:
        store.record_for_case(**event)
    capture_store.mark_investigation_finalized(str(capture["id"]))


def _capture_parameters(capture: dict[str, Any]) -> dict[str, Any]:
    return {
        "capture_id": capture["id"],
        "capture_filter": capture.get("capture_filter", ""),
        "duration_limit_seconds": capture.get("duration_seconds"),
        "packet_limit": capture.get("packet_limit"),
        "size_limit_mib": capture.get("max_size_mib"),
        "snapshot_length": capture.get("snap_length"),
        "promiscuous": capture.get("promiscuous"),
    }


def _capture_filename(capture: dict[str, Any]) -> str:
    stamp = datetime.fromtimestamp(float(capture["created_at"])).astimezone()
    interface = "".join(
        character if character.isalnum() or character in "._-" else "-"
        for character in str(capture["interface"])
    ).strip(".-_") or "interface"
    return f"{stamp:%Y%m%d%H%M%S}-{interface[:100]}-capture.pcap"
