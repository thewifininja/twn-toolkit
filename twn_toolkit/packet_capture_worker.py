from __future__ import annotations

import argparse
import signal
import threading

from .packet_capture import PacketCaptureStore, run_packet_capture
from .packet_capture_investigation import finalize_pending_packet_captures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance", required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    store = PacketCaptureStore(args.instance)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stopping.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stopping.set())
    try:
        capture = store.begin(args.capture_id)
        result = run_packet_capture(
            {
                "interface": capture["interface"],
                "capture_filter": capture["capture_filter"],
                "duration_seconds": capture["duration_seconds"],
                "packet_count": capture["packet_limit"],
                "max_size_mib": capture["max_size_mib"],
                "snap_length": capture["snap_length"],
                "promiscuous": capture["promiscuous"],
            },
            instance_path=args.instance,
            output_path=capture["output_path"],
            should_stop=lambda: (
                stopping.is_set() or store.stop_requested(args.capture_id)
            ),
            progress=lambda values: store.progress(args.capture_id, values),
        )
        status = (
            "stopped"
            if result["termination_reason"] == "stopped by user"
            else "completed"
        )
        store.finish(args.capture_id, status=status, result=result)
        finalize_pending_packet_captures(
            args.instance, capture_id=args.capture_id
        )
        return 0
    except Exception as exc:
        store.finish(args.capture_id, status="error", error=str(exc))
        finalize_pending_packet_captures(
            args.instance, capture_id=args.capture_id
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
