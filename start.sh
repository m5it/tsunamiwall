#!/bin/bash
# Start TsunamiWall daemon in the background, then open the live TUI watch.
# When you press 'q' in the TUI, the daemon is stopped automatically.
# If a previous daemon left orphan sockets, this script cleans them up first.

set -eu

CONFIG="${1:-$HOME/.config/tsunamiwall/config.yaml}"
PID_FILE="/run/tsunamiwall/daemon.pid"
LOG_FILE="/tmp/tsunamiwall-daemon.log"

echo "Starting TsunamiWall daemon with config: $CONFIG"

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

# After the TUI exits, stop the daemon cleanly.
echo "Stopping daemon..."
./run.sh -c "$CONFIG" reset > /dev/null 2>&1 || true

echo "TsunamiWall stopped."
