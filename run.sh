#!/bin/sh
# Convenience wrapper to run TsunamiWall with sudo using the local venv.
# Usage:
#   ./run.sh start
#   ./run.sh -c /etc/tsunamiwall/config.yaml start
#   ./run.sh status
#   ./run.sh reset

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${SCRIPT_DIR}/.venv/bin/python"

if [ ! -x "${PYTHON}" ]; then
    echo "Virtualenv Python not found at ${PYTHON}" >&2
    echo "Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi

exec sudo "${PYTHON}" "${SCRIPT_DIR}/main.py" "$@"
