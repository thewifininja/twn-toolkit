from __future__ import annotations

import argparse
import signal
import sqlite3
import threading
import traceback

from .activity import ActivityStore
from .iperf_server import (
    IperfServerStore,
    run_managed_iperf3_server,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", required=True)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--session-id", required=True)
    args = parser.parse_args()

    store = IperfServerStore(args.instance)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stopping.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stopping.set())

    try:
        session = store.begin(args.session_id)
        run_managed_iperf3_server(
            {
                "bind_address": session["bind_address"],
                "port": session["port"],
            },
            should_stop=lambda: (
                stopping.is_set()
                or store.stop_requested(args.session_id)
            ),
            result_completed=lambda result: _complete_result(
                store,
                args.session_id,
                args.instance,
                session,
                result,
            ),
            transient_error=lambda message: store.record_transient_error(
                args.session_id, message
            ),
            process_started=lambda pid: store.set_iperf_pid(
                args.session_id, pid
            ),
        )
        if store.desired_active(args.session_id):
            store.pause(
                args.session_id,
                reason="Toolkit service stopped; waiting to resume.",
            )
        else:
            store.finish(
                args.session_id,
                status="stopped",
                reason="stopped by user",
            )
        return 0
    except Exception as exc:
        if store.desired_active(args.session_id):
            traceback.print_exc()
            store.finish(
                args.session_id,
                status="error",
                reason="worker failed",
                error=f"{type(exc).__name__}: {exc}",
            )
        else:
            store.finish(
                args.session_id,
                status="stopped",
                reason="stopped before listener startup",
            )
        return 1


def _complete_result(
    store: IperfServerStore,
    session_id: str,
    instance_path: str,
    session: dict,
    result: dict,
) -> None:
    if store.record_result(session_id, result):
        _record_activity(instance_path, session, result)


def _record_activity(
    instance_path: str,
    session: dict,
    result: dict,
) -> None:
    try:
        store = ActivityStore(instance_path)
        store.increment(
            "speedtest",
            "runs",
            1,
            user_id=str(session.get("created_by", "")),
            username=str(session.get("created_by_username", "")),
        )
        store.increment(
            "speedtest",
            "bytes_transferred",
            int(result.get("transferred_bytes") or 0),
            user_id=str(session.get("created_by", "")),
            username=str(session.get("created_by_username", "")),
        )
    except (OSError, sqlite3.Error, ValueError):
        pass


if __name__ == "__main__":
    raise SystemExit(main())
