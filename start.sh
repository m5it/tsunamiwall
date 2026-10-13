#!/bin/bash
# Start TsunamiWall daemon in the background, then open the live TUI watch.
# When you press 'q' in the TUI, the daemon is stopped automatically.
# If a previous daemon left orphan sockets, this script cleans them up first.

set -eu

CONFIG="${1:-$HOME/.config/tsunamiwall/config.yaml}"
PID_FILE="/run/tsunamiwall/daemon.pid"
LOG_FILE="/tmp/tsunamiwall-daemon.log"

echo "Starting TsunamiWall daemon with config: $CONFIG"

# Ask for sudo password once at the very beginning and keep credentials alive
# while the TUI is open, so pressing 'q' does not prompt again.
echo "This script needs sudo to manage iptables and the daemon."
sudo -v
# Refresh sudo credentials in the background every 30 seconds.
(
    while true; do
        sleep 30
        sudo -n true 2>/dev/null || exit 0
    done
) &
SUDO_KEEPALIVE_PID=$!

cleanup() {
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
}
trap cleanup EXIT

# If a daemon is already reachable, just open the TUI; do not start a second daemon.
if ./run.sh -c "$CONFIG" status > /dev/null 2>&1; then
    echo "Daemon is already running. Opening TUI..."
    ./run.sh -c "$CONFIG" watch
    echo "TUI closed; daemon is still running in the background."
    exit 0
fi

# No reachable daemon. Kill any leftover tsunamiwall processes and wait for
# their sockets to close so a fresh daemon can bind its honeypots.
echo "Cleaning up any leftover TsunamiWall processes..."
sudo pkill -f 'tsunamiwall/main.py' || true
sleep 3

for i in $(seq 1 20); do
    COUNT=$(ss -tln 2>/dev/null | awk '$4 ~ /:10[0-9]{3}\>/' | wc -l)
    if [ "$COUNT" -eq 0 ]; then
        echo "Orphan sockets closed."
        break
    fi
    echo "Waiting for $COUNT orphan sockets to close..."
    sleep 1
done

nohup ./run.sh -c "$CONFIG" start > "$LOG_FILE" 2>&1 &

# Wait for the daemon to become reachable (up to 60 seconds).
for i in $(seq 1 60); do
    if ./run.sh -c "$CONFIG" status > /dev/null 2>&1; then
        echo "Daemon started."
        break
    fi
    sleep 1
done

if ! ./run.sh -c "$CONFIG" status > /dev/null 2>&1; then
    echo "Daemon failed to start; see $LOG_FILE"
    exit 1
fi

echo "Opening live TUI (press 'q' to quit and stop the daemon)..."
./run.sh -c "$CONFIG" watch

# After the TUI exits, stop the daemon gracefully. Send the CLI stop command,
# then wait for the process to actually exit; fall back to SIGTERM/SIGKILL.
echo "Stopping daemon (this may take a few seconds)..."
./run.sh -c "$CONFIG" stop > /dev/null 2>&1 || true

# Wait up to 15 seconds for the daemon PID file to disappear / process to exit.
for i in $(seq 1 15); do
    if [ ! -f "$PID_FILE" ]; then
        break
    fi
    DAEMON_PID=$(cat "$PID_FILE")
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done

if [ -f "$PID_FILE" ]; then
    DAEMON_PID=$(cat "$PID_FILE")
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "Graceful stop did not finish; sending SIGTERM to PID $DAEMON_PID..."
        sudo kill -TERM "$DAEMON_PID" || true
        sleep 5
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            echo "Daemon still alive; forcing kill..."
            sudo kill -9 "$DAEMON_PID" || true
            sleep 2
        fi
    fi
fi

# Also clean up any remaining tsunamiwall processes just in case.
sudo pkill -f 'tsunamiwall/main.py' || true

echo "TsunamiWall stopped."
