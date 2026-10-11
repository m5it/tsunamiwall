#!/bin/sh
# Development wrapper: run TsunamiWall from the local venv as root.
# Same as run.sh but also installs the package in editable mode if missing.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${SCRIPT_DIR}/.venv/bin/python"

if [ ! -x "${PYTHON}" ]; then
    echo "Creating virtualenv..." >&2
    python3 -m venv "${SCRIPT_DIR}/.venv"
fi

if [ ! -d "${SCRIPT_DIR}/.venv/lib" ]; then
    echo "Installing dependencies in editable mode..." >&2
    "${PYTHON}" -m pip install -r "${SCRIPT_DIR}/requirements-dev.txt"
    "${PYTHON}" -m pip install -e "${SCRIPT_DIR}"
fi

exec sudo "${PYTHON}" "${SCRIPT_DIR}/main.py" "$@"
