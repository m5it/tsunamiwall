#!/bin/sh
# Convenience wrapper to run TsunamiWall with sudo using the local venv.
# Usage:
#   ./run.sh start
#   ./run.sh -c /etc/tsunamiwall/config.yaml start
#   ./run.sh status
#   ./run.sh reset
#
# If no --config/-c is given, this wrapper defaults to the caller's own
# ~/.config/tsunamiwall/config.yaml before elevating with sudo. That prevents
# sudo from switching $HOME to /root and loading a different config.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${SCRIPT_DIR}/.venv/bin/python"

if [ ! -x "${PYTHON}" ]; then
    echo "Virtualenv Python not found at ${PYTHON}" >&2
    echo "Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi

# Default to the non-root user's config when no explicit config path is given.
has_config=0
for arg in "$@"; do
    if [ "$arg" = "-c" ] || [ "$arg" = "--config" ]; then
        has_config=1
        break
    fi
done

if [ "$has_config" -eq 0 ]; then
    USER_HOME="${HOME:-$(getent passwd "${SUDO_USER:-${USER:-$(whoami)}}" | cut -d: -f6)}"
    DEFAULT_CONFIG="${USER_HOME}/.config/tsunamiwall/config.yaml"
    if [ -f "${DEFAULT_CONFIG}" ]; then
        set -- -c "${DEFAULT_CONFIG}" "$@"
    fi
fi

exec sudo "${PYTHON}" "${SCRIPT_DIR}/main.py" "$@"
