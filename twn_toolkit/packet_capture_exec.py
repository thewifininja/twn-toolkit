from __future__ import annotations

import os
import resource
import sys


def main() -> int:
    if len(sys.argv) < 3:
        return 2
    try:
        max_bytes = int(sys.argv[1])
    except ValueError:
        return 2
    if max_bytes < 24:
        return 2
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))
    os.execv(sys.argv[2], sys.argv[2:])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
