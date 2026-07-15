from __future__ import annotations

import argparse
from pathlib import Path

from .upgrade_manager import execute_request


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a prepared toolkit upgrade operation.")
    parser.add_argument("--request", required=True)
    args = parser.parse_args()
    execute_request(Path(args.request))


if __name__ == "__main__":
    main()
