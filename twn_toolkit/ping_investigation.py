from __future__ import annotations

import csv
import io
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .investigations import InvestigationError, InvestigationStore
from .live_tools import LiveToolStore


class PingInvestigationError(RuntimeError):
    pass


def recording_case_id(instance_path: str | Path, user_id: str) -> str:
    investigation = InvestigationStore(instance_path).active_for_user(user_id)
    if not investigation or not investigation.get("is_recording"):
        return ""
    return str(investigation["id"])


def record_ping_session_started(
    instance_path: str | Path,
    *,
    session: dict[str, Any],
    targets: list[dict[str, str]],
    interval: int,
    timeout: float,
) -> dict[str, Any] | None:
    investigation_id = str(session.get("investigation_id", ""))
    if not investigation_id:
        return None
    target_names = [_target_name(target) for target in targets]
    target_summary = _joined_names(target_names)
    return InvestigationStore(instance_path).record_for_case(
        investigation_id=investigation_id,
        user_id=str(session.get("_user_id", "")),
        username=str(session.get("_username", "")),
        require_recording=True,
        operation_id=f"ping-live-start:{session['id']}",
        event_type="ping.session.started",
        tool_id="tools.ping",
        action="Ping started",
        outcome="info",
        summary=(
            f"Started monitoring {target_summary} every {interval} seconds."
        ),
        targets=targets,
        parameters={
            "session_id": session["id"],
            "title": session["title"],
            "interval_seconds": interval,
            "timeout_seconds": timeout,
            "configuration_revision": 1,
        },
        metrics={"target_count": len(targets)},
        details={},
        started_at=float(session["created_at"]),
        completed_at=float(session["created_at"]),
    )


def finalize_pending_ping_sessions(
    instance_path: str | Path,
    *,
    user_id: str = "",
    investigation_id: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    live_store = LiveToolStore(str(instance_path))
    sessions = live_store.pending_ping_investigation_sessions(
        user_id=user_id,
        investigation_id=investigation_id,
        session_id=session_id,
    )
    finalized: list[str] = []
    failures: list[dict[str, str]] = []
    for session in sessions:
        try:
            _finalize_ping_session(instance_path, live_store, session)
        except (InvestigationError, OSError, PingInvestigationError, ValueError) as exc:
            failures.append({"session_id": str(session["id"]), "error": str(exc)})
        else:
            finalized.append(str(session["id"]))
    return {"finalized": finalized, "failures": failures}


def stop_and_finalize_case_ping_sessions(
    instance_path: str | Path,
    *,
    investigation_id: str,
    user_id: str,
) -> dict[str, Any]:
    live_store = LiveToolStore(str(instance_path))
    stopped = live_store.stop_ping_sessions_for_investigation(
        investigation_id, user_id=user_id
    )
    result = finalize_pending_ping_sessions(
        instance_path,
        user_id=user_id,
        investigation_id=investigation_id,
    )
    if result["failures"]:
        first = result["failures"][0]
        raise PingInvestigationError(
            "The case remains open because Ping evidence could not be "
            f"retained: {first['error']}"
        )
    return {"stopped": len(stopped), "finalized": len(result["finalized"])}


def _finalize_ping_session(
    instance_path: str | Path,
    live_store: LiveToolStore,
    session: dict[str, Any],
) -> None:
    result = live_store.ping_investigation_result(str(session["id"]))
    if result is None:
        raise PingInvestigationError("The Ping session no longer exists.")
    session = result["session"]
    samples = result["samples"]
    epochs = result["configuration_epochs"]
    stopped_at = float(session.get("stopped_at") or session.get("updated_at"))
    target_summaries = _target_summaries(samples, epochs)
    omitted_target_summaries = max(0, len(target_summaries) - 500)
    retained_target_summaries = target_summaries[:500]
    retained_epochs, omitted_epochs = _bounded_epochs(epochs)
    probes_sent = int(session.get("probes_sent") or 0)
    replies_received = int(session.get("replies_received") or 0)
    sample_count = len(samples)
    sample_omissions = max(0, probes_sent - sample_count)
    reason = str(session.get("stop_reason") or "manual")
    outcome = {
        "error": "failed",
        "lease_expired": "incomplete",
    }.get(reason, "succeeded" if probes_sent else "incomplete")
    summary = _completion_summary(
        session,
        retained_target_summaries,
        probes_sent=probes_sent,
        replies_received=replies_received,
        reason=reason,
    )
    filename = f"multi-ping-{session['id']}-samples.csv"
    content = _samples_csv(samples, epochs)
    evidence = InvestigationStore(instance_path).add_generated_evidence_event(
        investigation_id=str(session["investigation_id"]),
        user_id=str(session["_user_id"]),
        username=str(session["_username"]),
        operation_id=f"ping-live-final:{session['id']}",
        event_type="ping.session.completed",
        tool_id="tools.ping",
        action=_completion_action(reason),
        outcome=outcome,
        summary=summary,
        targets=_all_targets(epochs),
        parameters={
            "session_id": session["id"],
            "title": session["title"],
            "duration_seconds": round(
                max(0.0, stopped_at - float(session["created_at"])), 3
            ),
            "termination": reason,
            "configuration_revision_count": len(epochs),
        },
        metrics={
            "rounds": int(session.get("rounds_completed") or 0),
            "probes_sent": probes_sent,
            "replies_received": replies_received,
            "response_rate": round(
                (replies_received / probes_sent) * 100, 2
            )
            if probes_sent
            else 0,
            "retained_samples": sample_count,
            "omitted_samples": sample_omissions,
            "target_count": len(target_summaries),
            "observed_target_count": sum(
                1
                for target in target_summaries
                if int(target.get("retained_probes") or 0)
            ),
        },
        details={
            "target_summaries": retained_target_summaries,
            "omitted_target_summaries": omitted_target_summaries,
            "configuration_epochs": retained_epochs,
            "omitted_configuration_epochs": omitted_epochs,
            "last_engine": session.get("last_engine", ""),
            "last_error": session.get("last_error", ""),
        },
        started_at=stopped_at,
        completed_at=stopped_at,
        filename=filename,
        content_type="text/csv",
        content=content,
    )
    if not evidence.get("artifact"):
        raise PingInvestigationError("Ping evidence was not retained.")
    live_store.mark_ping_investigation_finalized(str(session["id"]))


def _target_summaries(
    samples: list[dict[str, Any]], epochs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for target in _all_targets(epochs):
        grouped[(target["host"], target["label"])]
    for sample in samples:
        grouped[(str(sample.get("host", "")), str(sample.get("label", "")))].append(
            sample
        )
    summaries: list[dict[str, Any]] = []
    for (host, label), target_samples in grouped.items():
        if not target_samples:
            summaries.append(
                {
                    "host": host,
                    "label": label,
                    "observation": "No probes completed",
                    "retained_probes": 0,
                    "replies_received": 0,
                    "response_rate": 0,
                    "initial_observation": "",
                    "final_observation": "",
                    "first_sample_at": "",
                    "last_sample_at": "",
                    "first_reply_at": "",
                    "last_reply_at": "",
                    "reply_interruptions": 0,
                    "minimum_latency_ms": None,
                    "average_latency_ms": None,
                    "maximum_latency_ms": None,
                }
            )
            continue
        replies = [sample for sample in target_samples if sample.get("reachable")]
        latencies = [
            float(sample["latency_ms"])
            for sample in replies
            if sample.get("latency_ms") is not None
        ]
        reply_interruptions = 0
        reply_seen = False
        interruption_open = False
        for sample in target_samples:
            if sample.get("reachable"):
                reply_seen = True
                interruption_open = False
            elif reply_seen and not interruption_open:
                reply_interruptions += 1
                interruption_open = True
        replies_received = len(replies)
        sent = len(target_samples)
        summaries.append(
            {
                "host": host,
                "label": label,
                "observation": _observation(target_samples, replies_received),
                "retained_probes": sent,
                "replies_received": replies_received,
                "response_rate": round((replies_received / sent) * 100, 2)
                if sent
                else 0,
                "initial_observation": (
                    "reply" if target_samples[0].get("reachable") else "no_reply"
                ),
                "final_observation": (
                    "reply" if target_samples[-1].get("reachable") else "no_reply"
                ),
                "first_sample_at": _iso(target_samples[0]["sampled_at"]),
                "last_sample_at": _iso(target_samples[-1]["sampled_at"]),
                "first_reply_at": _iso(replies[0]["sampled_at"]) if replies else "",
                "last_reply_at": _iso(replies[-1]["sampled_at"]) if replies else "",
                "reply_interruptions": reply_interruptions,
                "minimum_latency_ms": round(min(latencies), 3) if latencies else None,
                "average_latency_ms": round(sum(latencies) / len(latencies), 3)
                if latencies
                else None,
                "maximum_latency_ms": round(max(latencies), 3) if latencies else None,
            }
        )
    return summaries


def _observation(samples: list[dict[str, Any]], replies: int) -> str:
    if not replies:
        return "No replies observed"
    if replies == len(samples):
        return "Replied to every retained probe"
    if not samples[0].get("reachable"):
        return "Replies observed after initial timeouts"
    if not samples[-1].get("reachable"):
        return "No reply to the final retained probe"
    return "Intermittent replies observed"


def _samples_csv(
    samples: list[dict[str, Any]], epochs: list[dict[str, Any]]
) -> bytes:
    epoch_by_revision = {
        int(epoch["revision"]): epoch for epoch in epochs
    }
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "sample_id",
            "sampled_at_utc",
            "configuration_revision",
            "label",
            "host",
            "reply_observed",
            "latency_ms",
            "interval_seconds",
            "timeout_seconds",
            "configuration_effective_at_utc",
        ]
    )
    for sample in samples:
        epoch = epoch_by_revision.get(int(sample["revision"]), {})
        config = epoch.get("config", {})
        writer.writerow(
            [
                sample["id"],
                _iso(sample["sampled_at"]),
                sample["revision"],
                sample["label"],
                sample["host"],
                "yes" if sample["reachable"] else "no",
                "" if sample["latency_ms"] is None else sample["latency_ms"],
                config.get("interval", ""),
                config.get("timeout", ""),
                _iso(epoch["effective_at"]) if epoch.get("effective_at") else "",
            ]
        )
    return output.getvalue().encode("utf-8")


def _bounded_epochs(
    epochs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    rendered = [
        {
            "revision": epoch["revision"],
            "effective_at": _iso(epoch["effective_at"]),
            "targets": epoch["config"].get("targets", []),
            "interval_seconds": epoch["config"].get("interval"),
            "timeout_seconds": epoch["config"].get("timeout"),
        }
        for epoch in epochs
    ]
    if len(rendered) <= 100:
        return rendered, 0
    return [*rendered[:50], *rendered[-50:]], len(rendered) - 100


def _all_targets(epochs: list[dict[str, Any]]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for epoch in epochs:
        for raw_target in epoch.get("config", {}).get("targets", []):
            target = {
                "host": str(raw_target.get("host", "")),
                "label": str(raw_target.get("label", "")),
            }
            identity = (target["host"], target["label"])
            if identity not in seen:
                targets.append(target)
                seen.add(identity)
    return targets[:1000]


def _completion_summary(
    session: dict[str, Any],
    target_summaries: list[dict[str, Any]],
    *,
    probes_sent: int,
    replies_received: int,
    reason: str,
) -> str:
    rounds = int(session.get("rounds_completed") or 0)
    if not probes_sent:
        base = "The session ended before any ping probes completed."
    else:
        base = (
            f"Completed {rounds} round{'s' if rounds != 1 else ''} and observed "
            f"{replies_received} repl{'ies' if replies_received != 1 else 'y'} "
            f"from {probes_sent} probes."
        )
    never_replied = [
        _target_name(target)
        for target in target_summaries
        if int(target.get("retained_probes") or 0)
        and not int(target.get("replies_received") or 0)
    ]
    if never_replied:
        base += f" No replies were observed from {_joined_names(never_replied)}."
    if reason == "lease_expired":
        base += " The browser lease expired, so the toolkit stopped the session."
    elif reason == "case_closed":
        base += " The toolkit stopped the session when the case was closed."
    elif reason == "error":
        base += " The session ended because the live monitor encountered an error."
    return base


def _completion_action(reason: str) -> str:
    return {
        "lease_expired": "Ping automatically stopped",
        "case_closed": "Ping stopped for case closure",
        "error": "Ping failed",
    }.get(reason, "Ping stopped")


def _target_name(target: dict[str, Any]) -> str:
    host = str(target.get("host", "")).strip()
    label = str(target.get("label", "")).strip()
    return f"{label} ({host})" if label and host else label or host or "unnamed target"


def _joined_names(names: list[str]) -> str:
    if not names:
        return "no targets"
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return f"{', '.join(names[:3])}{f' and {len(names) - 3} more' if len(names) > 3 else ''}"


def _iso(value: Any) -> str:
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
