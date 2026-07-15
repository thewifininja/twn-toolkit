#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV="$ROOT/.venv"
INSTANCE="$ROOT/instance"
FRESH_INSTALL=0
WAS_RUNNING=0

if [ ! -d "$INSTANCE" ] || [ -z "$(ls -A "$INSTANCE" 2>/dev/null)" ]; then
  FRESH_INSTALL=1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required but was not found in PATH." >&2
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
  echo "Python 3.10 or newer is required." >&2
  exit 1
fi

if [ -x "$VENV/bin/python" ] && "$ROOT/twn" status >/dev/null 2>&1; then
  WAS_RUNNING=1
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
mkdir -p "$INSTANCE"

if [ "$FRESH_INSTALL" -eq 1 ]; then
  echo "Generating the default local HTTPS certificate..."
  "$ROOT/twn" enable-https
fi

echo "Starting The WiFi Ninja's Toolkit..."
if [ "$WAS_RUNNING" -eq 1 ]; then
  "$ROOT/twn" restart
else
  "$ROOT/twn" start
fi
touch "$INSTANCE/installation.initialized"
TOOLKIT_URL=$("$ROOT/twn" status | tail -n 1)

echo
echo "Installation complete."
echo "Open $TOOLKIT_URL to create the administrator account."
if [ "$FRESH_INSTALL" -eq 1 ]; then
  echo "The generated certificate is self-signed, so your browser will require you to review its warning before continuing."
fi
