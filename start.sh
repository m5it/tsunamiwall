#!/bin/bash
# start in background. later overview with TUI watch
nohup ./run.sh -c ~/.config/tsunamiwall/config.yaml start > /tmp/tsunamiwall-daemon.log 2>&1 & echo $! > /tmp/tsunamiwall-pid.txt
PID=$(cat /tmp/tsunamiwall-pid.txt)
echo "Please wait. Now starting TUI preview trough \"watch\" command! PID: "$PID
sleep 3
./run.sh -c ~/.config/tsunamiwall/config.yaml watch
