#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV="$ROOT/.venv"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required but was not found in PATH." >&2
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
  echo "Python 3.10 or newer is required." >&2
  exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
  echo "Creating Python virtual environment..."
  python3 -m venv "$VENV"
fi

echo "Updating packaging tools..."
"$VENV/bin/python" -m pip install --upgrade pip

echo "Installing toolkit requirements..."
"$VENV/bin/python" -m pip install -r "$ROOT/requirements.txt"

chmod +x "$ROOT/twn"
mkdir -p "$ROOT/instance"

echo "Starting The WiFi Ninja's Toolkit..."
"$ROOT/twn" start

echo
echo "Installation complete."
echo "Open http://127.0.0.1:${TWN_TOOLKIT_PORT:-5050} to create the administrator account."
