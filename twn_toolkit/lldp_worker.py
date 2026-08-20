from __future__ import annotations

import argparse
import signal
import threading
import time

from .lldp_sessions import LLDPSessionStore
from .lldp_tools import (
    local_lldpd_shutdown_frame,
    quiet_interface_lldp,
    restore_interface_lldp,
)
from .investigations import InvestigationStore
from .packet_replay_tools import send_replay_frames


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", required=True)
    parser.add_argument("--session-id", required=True)
    args = parser.parse_args()
    store = LLDPSessionStore(args.instance)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stopping.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stopping.set())
    frames_sent = 0
    session = None
    final_status = "error"
    error = ""
    prior_lldpd_status = ""
    try:
        session = store.begin(args.session_id)
        if session["persona"].get("quiet_lldpd"):
            local_shutdown = local_lldpd_shutdown_frame(session["interface"])
            prior_lldpd_status = quiet_interface_lldp(session["interface"])
            if local_shutdown and prior_lldpd_status:
                # Remove the host identity from the adjacent device immediately
                # instead of waiting for its previously advertised TTL to expire.
                send_replay_frames(
                    [local_shutdown],
                    interface=session["interface"],
                    interval_seconds=0.1,
                )
        started = time.monotonic()
        final_status = "completed"
        while True:
            if stopping.is_set() or store.stop_requested(args.session_id):
                final_status = "stopped"
                break
            if time.monotonic() - started >= int(session["duration_seconds"]):
                break
            send_replay_frames(
                [bytes.fromhex(session["frame_hex"])],
                interface=session["interface"],
                interval_seconds=0.1,
            )
            frames_sent += 1
            store.progress(args.session_id, frames_sent=frames_sent)
            deadline = time.monotonic() + int(session["interval_seconds"])
            while time.monotonic() < deadline:
                if stopping.is_set() or store.stop_requested(args.session_id):
                    final_status = "stopped"
                    break
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
            if final_status == "stopped":
                break
    except Exception as exc:
        error = str(exc)
        final_status = "error"
    finally:
        if session and frames_sent:
            try:
                # Expire a partially or fully advertised identity even after an error.
                send_replay_frames(
                    [bytes.fromhex(session["shutdown_frame_hex"])],
                    interface=session["interface"],
                    interval_seconds=0.1,
                )
            except Exception as shutdown_exc:
                if not error:
                    error = f"The shutdown PDU could not be sent: {shutdown_exc}"
        if session and prior_lldpd_status:
            try:
                restore_interface_lldp(session["interface"], prior_lldpd_status)
            except Exception as restore_exc:
                restore_error = f"The original lldpd interface state could not be restored: {restore_exc}"
                error = f"{error} {restore_error}".strip()
                final_status = "error"
        store.finish(args.session_id, status=final_status, error=error)
        if session and session.get("investigation_id") and final_status in {"completed", "stopped", "error"}:
            try:
                now = time.time()
                InvestigationStore(args.instance).record_for_case(
                    investigation_id=str(session["investigation_id"]),
                    user_id=str(session["created_by"]),
                    username=str(session["created_by_username"]),
                    require_recording=True,
                    operation_id=f"lldp-emission:{args.session_id}:complete",
                    event_type=(
                        "action.completed"
                        if final_status == "completed"
                        else "action.stopped"
                        if final_status == "stopped"
                        else "action.failed"
                    ),
                    tool_id="tools.lldp_lab",
                    action="LLDP identity emission",
                    outcome=(
                        "succeeded"
                        if final_status == "completed"
                        else "stopped"
                        if final_status == "stopped"
                        else "failed"
                    ),
                    summary=(
                        f"Completed LLDP persona {session['persona_name']} on "
                        f"{session['interface']} after {frames_sent} frame(s)."
                        if final_status == "completed"
                        else (
                            f"Stopped LLDP persona {session['persona_name']} on "
                            f"{session['interface']} after {frames_sent} frame(s)."
                        )
                        if final_status == "stopped"
                        else f"LLDP persona {session['persona_name']} failed: {error}"
                    ),
                    targets={"interface": session["interface"]},
                    parameters={
                        "persona": session["persona_name"],
                        "interval_seconds": session["interval_seconds"],
                        "duration_seconds": session["duration_seconds"],
                    },
                    metrics={"frames_sent": frames_sent},
                    details={"error": error},
                    started_at=float(session.get("started_at") or session["created_at"]),
                    completed_at=now,
                )
            except Exception:
                # Case state may have changed while the bounded session was running.
                pass
    return 0 if final_status in {"completed", "stopped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
