#!/usr/bin/env python3
"""Bootstrap guided setup before the toolkit virtual environment exists."""
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from twn_toolkit.setup_cli import main

if __name__ == '__main__':
    raise SystemExit(main())
