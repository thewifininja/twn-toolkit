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

BOOTSTRAP_PYTHON=${TWN_TOOLKIT_PYTHON:-python3}
if [ -z "${TWN_TOOLKIT_PYTHON:-}" ] && [ -x "$VENV/bin/python" ]; then
  BOOTSTRAP_PYTHON="$VENV/bin/python"
fi
if ! command -v "$BOOTSTRAP_PYTHON" >/dev/null 2>&1; then
  echo "Python 3.11 or newer is required. Set TWN_TOOLKIT_PYTHON to its executable path." >&2
  exit 1
fi
if ! "$BOOTSTRAP_PYTHON" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
  echo "Python 3.11 or newer is required. Set TWN_TOOLKIT_PYTHON to a supported interpreter." >&2
  echo "Existing files and packages have not been changed. See docs/python-upgrade.md." >&2
  exit 1
fi
if [ -x "$VENV/bin/python" ] && ! "$VENV/bin/python" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
  echo "The existing .venv uses an unsupported Python. It has not been changed." >&2
  echo "Stop the old toolkit and preserve its environment before rebuilding with Python 3.11+. See docs/python-upgrade.md." >&2
  exit 1
fi

# Interactive onboarding is separate from the unattended upgrade/rollback contract.
PREPARE_ONLY=0
GUIDED=auto
for argument in "$@"; do
  case "$argument" in
    --guided) GUIDED=1 ;;
    --non-interactive) GUIDED=0 ;;
    --prepare-only) PREPARE_ONLY=1; GUIDED=0 ;;
    *) echo "Usage: ./install.sh [--guided|--non-interactive]" >&2; exit 2 ;;
  esac
done
if [ -n "$INSTALL_STATUS_FILE" ] || [ -n "${TWN_TOOLKIT_UPGRADE_REQUEST_ID:-}" ] || [ -n "${TWN_TOOLKIT_SETUP_ACTIVE:-}" ]; then
  GUIDED=0
fi
if [ "$GUIDED" = 1 ] || { [ "$GUIDED" = auto ] && [ -t 0 ] && [ -t 1 ] && [ "$FRESH_INSTALL" -eq 1 ]; }; then
  export TWN_TOOLKIT_PYTHON="$BOOTSTRAP_PYTHON"
  exec "$BOOTSTRAP_PYTHON" "$ROOT/scripts/guided_install.py"
fi

if [ -x "$VENV/bin/python" ] && "$ROOT/twn" status >/dev/null 2>&1; then
  WAS_RUNNING=1
fi

if [ ! -x "$VENV/bin/python" ]; then
  INSTALL_STAGE=virtual-environment
  echo "Creating Python virtual environment..."
  "$BOOTSTRAP_PYTHON" -m venv "$VENV"
fi

INSTALL_STAGE=dependency-lock
"$VENV/bin/python" "$ROOT/scripts/lock_dependencies.py" --check

INSTALL_STAGE=packaging-tools
echo "Updating packaging tools..."
"$VENV/bin/python" -m pip install --upgrade pip

INSTALL_STAGE=requirements
echo "Installing toolkit requirements..."
"$VENV/bin/python" -m pip install --require-hashes -r "$ROOT/requirements.txt"
"$VENV/bin/python" -m pip check

chmod +x "$ROOT/twn"
mkdir -p "$INSTANCE"

if [ "$PREPARE_ONLY" -eq 1 ]; then
  INSTALL_STAGE=complete
  echo "Python environment prepared; settings and startup are managed by guided setup."
  exit 0
fi

if [ "$FRESH_INSTALL" -eq 1 ]; then
  INSTALL_STAGE=https-certificate
  echo "Generating the default local HTTPS certificate..."
  "$ROOT/twn" enable-https
fi

INSTALL_STAGE=toolkit-start
echo "Starting TWN Toolkit..."
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
  echo "Optional high-capacity Ping support is available through fping."
else
  echo "Optional high-capacity Ping support is unavailable. Install and authorize fping, then restart the toolkit, to raise the Ping limit from 100 to 250 targets."
fi
INSTALL_STAGE=complete
