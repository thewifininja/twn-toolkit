"""One API request; credentials travel through stdin, never argv or files."""
from __future__ import annotations

import json
import os
import sys
import threading
import time


def main():
    envelope = json.load(sys.stdin)
    deadline = envelope["deadline"]
    parent = envelope["parent"]

    def watch():
        while True:
            if os.getppid() != parent or time.monotonic() >= deadline:
                os._exit(124)
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))

    threading.Thread(target=watch, daemon=True).start()
    # Start the watchdog before importing networking libraries or resolving DNS.
    from .diagnostic_tools import _send_api_request
    from .network_tools import ToolInputError
    try:
        message = {"result": _send_api_request(**envelope["request"])}
    except ToolInputError as exc:
        message = {"error": str(exc)}
    json.dump(message, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
