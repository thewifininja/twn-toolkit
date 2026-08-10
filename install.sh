#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV="$ROOT/.venv"
INSTANCE="$ROOT/instance"
FRESH_INSTALL=0
WAS_RUNNING=0
INSTALL_STATUS_FILE=${TWN_TOOLKIT_INSTALL_STATUS_FILE:-}
INSTALL_STAGE=preflight

record_install_result() {
  INSTALL_RESULT=$?
  if [ -n "$INSTALL_STATUS_FILE" ]; then
    if [ "$INSTALL_RESULT" -eq 0 ]; then
      INSTALL_STATE=succeeded
    else
      INSTALL_STATE=failed
    fi
    (umask 077 && printf '%s:%s:%s\n' "$INSTALL_STATE" "$INSTALL_STAGE" "$INSTALL_RESULT" > "$INSTALL_STATUS_FILE") || :
    chmod 600 "$INSTALL_STATUS_FILE" 2>/dev/null || :
  fi
  trap - 0
  exit "$INSTALL_RESULT"
}

trap record_install_result 0

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
  INSTALL_STAGE=virtual-environment
  echo "Creating Python virtual environment..."
  python3 -m venv "$VENV"
fi

INSTALL_STAGE=packaging-tools
echo "Updating packaging tools..."
"$VENV/bin/python" -m pip install --upgrade pip

INSTALL_STAGE=requirements
echo "Installing toolkit requirements..."
"$VENV/bin/python" -m pip install -r "$ROOT/requirements.txt"

chmod +x "$ROOT/twn"
mkdir -p "$INSTANCE"

if [ "$FRESH_INSTALL" -eq 1 ]; then
  INSTALL_STAGE=https-certificate
  echo "Generating the default local HTTPS certificate..."
  "$ROOT/twn" enable-https
fi

INSTALL_STAGE=toolkit-start
echo "Starting The WiFi Ninja's Toolkit..."
if [ "$WAS_RUNNING" -eq 1 ]; then
  TWN_TOOLKIT_RELOAD_SERVICE_LAUNCHER=1 "$ROOT/twn" restart
else
  TWN_TOOLKIT_RELOAD_SERVICE_LAUNCHER=1 "$ROOT/twn" start
fi
touch "$INSTANCE/installation.initialized"
INSTALL_STAGE=toolkit-status
TOOLKIT_URL=$("$ROOT/twn" status | tail -n 1)

echo
echo "Installation complete."
echo "Open $TOOLKIT_URL to create the administrator account."
if [ "$FRESH_INSTALL" -eq 1 ]; then
  echo "The generated certificate is self-signed, so your browser will require you to review its warning before continuing."
fi
if command -v fping >/dev/null 2>&1 && fping -C 1 -q -r 0 -t 250 127.0.0.1 >/dev/null 2>&1; then
  echo "Optional high-capacity Multi-Ping support is available through fping."
else
  echo "Optional high-capacity Multi-Ping support is unavailable. Install and authorize fping, then restart the toolkit, to raise the Multi-Ping limit from 100 to 250 targets."
fi
INSTALL_STAGE=complete
