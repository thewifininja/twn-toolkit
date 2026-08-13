from __future__ import annotations

import csv
import io
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean
from typing import Any

from .investigations import InvestigationError, InvestigationStore
from .live_tools import LiveToolStore


class SnmpInvestigationError(RuntimeError):
    pass


def record_snmp_monitor_started(
    instance_path: str | Path,
    *,
    session: dict[str, Any],
    targets: list[dict[str, Any]],
    interval: int,
) -> dict[str, Any] | None:
    investigation_id = str(session.get("investigation_id", ""))
    if not investigation_id:
        return None
    names = [_target_name(target) for target in targets]
    return InvestigationStore(instance_path).record_for_case(
        investigation_id=investigation_id,
        user_id=str(session.get("_user_id", "")),
        username=str(session.get("_username", "")),
        require_recording=True,
        operation_id=f"snmp-interface-start:{session['id']}",
        event_type="snmp.monitor.started",
        tool_id="tools.snmp_test",
        action="SNMP bandwidth monitor started",
        outcome="info",
        summary=(
            f"Started monitoring {_joined_names(names)} every {interval} seconds."
        ),
        targets=targets,
        parameters={
            "session_id": session["id"],
            "title": session["title"],
            "interval_seconds": interval,
        },
        metrics={"interface_count": len(targets)},
        details={},
        started_at=float(session["created_at"]),
        completed_at=float(session["created_at"]),
    )


def finalize_pending_snmp_sessions(
    instance_path: str | Path,
    *,
    user_id: str = "",
    investigation_id: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    live_store = LiveToolStore(str(instance_path))
    sessions = live_store.pending_snmp_investigation_sessions(
        user_id=user_id,
        investigation_id=investigation_id,
        session_id=session_id,
    )
    finalized: list[str] = []
    failures: list[dict[str, str]] = []
    for session in sessions:
        try:
            _finalize_snmp_session(instance_path, live_store, session)
        except (InvestigationError, OSError, SnmpInvestigationError, ValueError) as exc:
            failures.append({"session_id": str(session["id"]), "error": str(exc)})
        else:
            finalized.append(str(session["id"]))
    return {"finalized": finalized, "failures": failures}


def stop_and_finalize_case_snmp_sessions(
    instance_path: str | Path,
    *,
    investigation_id: str,
    user_id: str,
) -> dict[str, Any]:
    live_store = LiveToolStore(str(instance_path))
    stopped = live_store.stop_snmp_sessions_for_investigation(
        investigation_id, user_id=user_id
    )
    result = finalize_pending_snmp_sessions(
        instance_path,
        user_id=user_id,
        investigation_id=investigation_id,
    )
    if result["failures"]:
        first = result["failures"][0]
        raise SnmpInvestigationError(
            "The case remains open because SNMP monitor evidence could not be "
            f"retained: {first['error']}"
        )
    return {"stopped": len(stopped), "finalized": len(result["finalized"])}


def _finalize_snmp_session(
    instance_path: str | Path,
    live_store: LiveToolStore,
    session: dict[str, Any],
) -> None:
    result = live_store.snmp_investigation_result(str(session["id"]))
    if result is None:
        raise SnmpInvestigationError("The SNMP monitor no longer exists.")
    session = result["session"]
    samples = _rated_samples(result["samples"])
    stopped_at = float(session.get("stopped_at") or session.get("updated_at"))
    reason = str(session.get("stop_reason") or "manual")
    summaries = _target_summaries(session.get("config", {}).get("targets", []), samples)
    polls = int(session.get("probes_sent") or 0)
    successful = int(session.get("replies_received") or 0)
    measurements = sum(1 for sample in samples if sample.get("download_bps") is not None)
    outcome = {
        "error": "failed",
        "lease_expired": "incomplete",
    }.get(reason, "succeeded" if polls else "incomplete")
    if not polls:
        summary = "Stopped the SNMP bandwidth monitor before any polls completed."
    else:
        summary = (
            f"Stopped SNMP bandwidth monitoring after {polls} poll(s): "
            f"{successful} succeeded and {polls - successful} failed."
        )
    filename = f"snmp-bandwidth-{session['id']}-samples.csv"
    evidence = InvestigationStore(instance_path).add_generated_evidence_event(
        investigation_id=str(session["investigation_id"]),
        user_id=str(session["_user_id"]),
        username=str(session["_username"]),
        operation_id=f"snmp-interface-final:{session['id']}",
        event_type="snmp.monitor.completed",
        tool_id="tools.snmp_test",
        action="SNMP bandwidth monitor stopped",
        outcome=outcome,
        summary=summary,
        targets=session.get("config", {}).get("targets", []),
        parameters={
            "session_id": session["id"],
            "title": session["title"],
            "interval_seconds": session.get("interval"),
            "duration_seconds": round(
                max(0.0, stopped_at - float(session["created_at"])), 3
            ),
            "termination": reason,
        },
        metrics={
            "interface_count": int(session.get("target_count") or 0),
            "rounds": int(session.get("rounds_completed") or 0),
            "polls": polls,
            "successful_polls": successful,
            "failed_polls": max(0, polls - successful),
            "rate_measurements": measurements,
            "retained_samples": len(samples),
        },
        details={
            "target_summaries": summaries[:500],
            "omitted_target_summaries": max(0, len(summaries) - 500),
            "last_error": session.get("last_error", ""),
        },
        started_at=stopped_at,
        completed_at=stopped_at,
        filename=filename,
        content_type="text/csv",
        content=_samples_csv(samples),
    )
    if not evidence.get("artifact"):
        raise SnmpInvestigationError("SNMP bandwidth evidence was not retained.")
    live_store.mark_snmp_investigation_finalized(str(session["id"]))


def _rated_samples(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    baselines: dict[str, dict[str, Any]] = {}
    retained: list[dict[str, Any]] = []
    for raw in samples:
        sample = dict(raw)
        payload = sample.get("sample") if isinstance(sample.get("sample"), dict) else {}
        target_key = str(sample.get("target_key", ""))
        sample["download_bps"] = None
        sample["upload_bps"] = None
        if sample.get("status") != "success" or not payload:
            retained.append(sample)
            continue
        current = _counter_baseline(payload)
        previous = baselines.get(target_key)
        baselines[target_key] = current
        if previous is None or _counter_reset(previous, current):
            retained.append(sample)
            continue
        elapsed = (current["sampled_at_ms"] - previous["sampled_at_ms"]) / 1000
        input_delta = _counter_delta(current["input"], previous["input"], current["bits"])
        output_delta = _counter_delta(current["output"], previous["output"], current["bits"])
        if elapsed > 0 and input_delta is not None and output_delta is not None:
            sample["download_bps"] = round(output_delta * 8 / elapsed, 3)
            sample["upload_bps"] = round(input_delta * 8 / elapsed, 3)
        retained.append(sample)
    return retained


def _counter_baseline(sample: dict[str, Any]) -> dict[str, Any]:
    return {
        "sampled_at_ms": int(sample.get("sampled_at_ms") or 0),
        "input": int(sample.get("input_octets") or 0),
        "output": int(sample.get("output_octets") or 0),
        "bits": int(sample.get("counter_bits") or 64),
        "uptime": sample.get("sys_uptime"),
        "discontinuity": sample.get("counter_discontinuity"),
    }


def _counter_reset(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    if previous["bits"] != current["bits"]:
        return True
    if (
        previous["uptime"] is not None
        and current["uptime"] is not None
        and current["uptime"] < previous["uptime"]
    ):
        return True
    return (
        previous["discontinuity"] is not None
        and current["discontinuity"] is not None
        and current["discontinuity"] != previous["discontinuity"]
    )


def _counter_delta(current: int, previous: int, bits: int) -> int | None:
    if current >= previous:
        return current - previous
    if bits == 32:
        return (1 << 32) - previous + current
    return None


def _target_summaries(
    targets: list[dict[str, Any]], samples: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        by_target[str(sample.get("target_key", ""))].append(sample)
    summaries = []
    for target in targets:
        key = f"{target.get('host_name', '')}::{target.get('interface_index', '')}"
        target_samples = by_target.get(key, [])
        successful = [sample for sample in target_samples if sample.get("status") == "success"]
        down = [float(sample["download_bps"]) for sample in successful if sample.get("download_bps") is not None]
        up = [float(sample["upload_bps"]) for sample in successful if sample.get("upload_bps") is not None]
        last_payload = next(
            (
                sample["sample"]
                for sample in reversed(successful)
                if isinstance(sample.get("sample"), dict)
            ),
            {},
        )
        summaries.append(
            {
                "host_name": str(target.get("host_name", "")),
                "host": str(target.get("host_address", "")),
                "interface_index": target.get("interface_index"),
                "interface_label": str(target.get("interface_label", "")),
                "successful_samples": len(successful),
                "failed_samples": len(target_samples) - len(successful),
                "rate_measurements": min(len(down), len(up)),
                "average_download_bps": round(fmean(down), 3) if down else None,
                "peak_download_bps": round(max(down), 3) if down else None,
                "average_upload_bps": round(fmean(up), 3) if up else None,
                "peak_upload_bps": round(max(up), 3) if up else None,
                "final_oper_status": last_payload.get("oper_status", ""),
                "final_input_errors": last_payload.get("input_errors"),
                "final_output_errors": last_payload.get("output_errors"),
                "final_input_discards": last_payload.get("input_discards"),
                "final_output_discards": last_payload.get("output_discards"),
            }
        )
    return summaries


def _samples_csv(samples: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    fields = [
        "sample_id", "sampled_at", "target_key", "status", "download_bps",
        "upload_bps", "input_octets", "output_octets", "counter_bits",
        "interface_status", "input_errors", "output_errors", "input_discards",
        "output_discards", "error",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for sample in samples:
        payload = sample.get("sample") if isinstance(sample.get("sample"), dict) else {}
        writer.writerow(
            {
                "sample_id": sample.get("id"),
                "sampled_at": _iso_time(sample.get("sampled_at")),
                "target_key": sample.get("target_key"),
                "status": sample.get("status"),
                "download_bps": sample.get("download_bps"),
                "upload_bps": sample.get("upload_bps"),
                "input_octets": payload.get("input_octets"),
                "output_octets": payload.get("output_octets"),
                "counter_bits": payload.get("counter_bits"),
                "interface_status": payload.get("oper_status"),
                "input_errors": payload.get("input_errors"),
                "output_errors": payload.get("output_errors"),
                "input_discards": payload.get("input_discards"),
                "output_discards": payload.get("output_discards"),
                "error": sample.get("error"),
            }
        )
    return output.getvalue().encode("utf-8")


def _iso_time(value: Any) -> str:
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return ""


def _target_name(target: dict[str, Any]) -> str:
    return (
        f"{target.get('host_name', 'device')} "
        f"{target.get('interface_label') or 'interface ' + str(target.get('interface_index', ''))}"
    ).strip()


def _joined_names(names: list[str]) -> str:
    if not names:
        return "the selected interfaces"
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return f"{', '.join(names[:3])}{' and others' if len(names) > 3 else ''}"
