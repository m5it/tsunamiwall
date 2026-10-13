# TsunamiWall Usage

## Requirements
- Linux server with Python 3.10+
- root privileges (for iptables and raw socket binding)
- `iptables` installed

## Installation

### Recommended: local virtualenv

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install -e .
```

Because `sudo` resets your PATH and hides the active virtualenv, always run with the absolute venv Python:

```bash
sudo .venv/bin/python main.py start
sudo .venv/bin/python main.py status
```

### Convenience wrapper

Two wrapper scripts are provided so you don't have to remember the full venv path:

```bash
./run.sh start
./run.sh -c /etc/tsunamiwall/config.yaml start
./run.sh status
./run.sh reset
```

`run-dev.sh` additionally creates the venv and installs deps if they are missing.

### System-wide install

```bash
pip install -e .
```

This installs two commands: `tsunamiwall` and `tsunamiwall-reset`.

## Important safety note
**Test on a non-production system first.** TsunamiWall changes your iptables `INPUT` chain and drops all unexpected inbound traffic. Make sure you have console access or a way to recover if you lock yourself out.

## Commands

### Start the daemon
```bash
sudo .venv/bin/python main.py start
# or:
./run.sh start
```
Runs in the foreground. Use systemd, supervisord, or `nohup`/`screen` to run it as a service.

### One-command start + TUI (`start.sh`)
The `start.sh` wrapper starts the daemon in the background, opens the live `watch` TUI, and gracefully stops the daemon when you press **q**:

```bash
./start.sh
# or with a custom config:
./start.sh /etc/tsunamiwall/config.yaml
```

### Stop the daemon gracefully
```bash
sudo .venv/bin/python main.py stop
# or:
./run.sh stop
```
This saves runtime state (allowed/blocked ports) and flushes TsunamiWall rules. Use this for normal shutdowns; use `reset` only for emergencies.

### Show current state
```bash
sudo .venv/bin/python main.py status
# or:
./run.sh status
```

### Explicitly allow a port
If you want to keep a port reachable even when nothing is currently listening, or just prefer manual control:
```bash
sudo .venv/bin/python main.py allow 8080
# or from a file:
sudo .venv/bin/python main.py allow --file config/allowed-ports-example.txt
```

### Remove an allowed/blocked port
```bash
sudo .venv/bin/python main.py deny 8080
```

### Block a port even if a service is listening
```bash
sudo .venv/bin/python main.py block 1337
sudo .venv/bin/python main.py unblock 1337
```

### Strict default-deny mode
Add this to your config to stop TsunamiWall from automatically allowing every listening socket:
```yaml
auto_block_listeners: true
```
In this mode only ports you explicitly `allow` are opened. Real services like SSH must be whitelisted manually, so make sure your management IP is in `trusted_ips` first.

### Allow a port only for a specific IP or CIDR
```bash
sudo .venv/bin/python main.py allow 8080 --ip 203.0.113.45
sudo .venv/bin/python main.py allow 8080 --ip 203.0.113.0/24
```

The rule is inserted before global `allow` rules, so it only opens the port for traffic coming from that source address or network. Use `deny` with the same `--ip` to remove it later.

Runtime allow/deny changes are persisted to `/run/tsunamiwall/daemon-state.json` and restored automatically when the daemon restarts, so your rules survive reboots or restarts (as long as `run_dir` is on persistent storage).

### View honeypot hits
```bash
sudo .venv/bin/python main.py logs
```

### Live honeypot hit monitor
Full-screen real-time table. Press **q** to quit.
```bash
sudo .venv/bin/python main.py watch
```

### Capture and inspect attacker payloads

TsunamiWall can read the data scanners send and store it by country/IP.

1. Install the optional offline geolocation dependency:
   ```bash
   .venv/bin/pip install iptocc
   # or
   .venv/bin/pip install -r requirements-geoip.txt
   ```

2. Enable payload capture in your config:
   ```yaml
   payload_max_bytes: 4096
   payload_read_timeout: 2.0
   payload_log_dir: "/var/log/tsunamiwall/bycountry"
   ```

3. After a probe, inspect the files:
   ```bash
   ls /var/log/tsunamiwall/bycountry/
   ls /var/log/tsunamiwall/bycountry/US/220.249.82.190/
   xxd /var/log/tsunamiwall/bycountry/US/220.249.82.190/*.bin
   ```

### Which ports are being blocked right now?

TsunamiWall drops everything by default, so the "blocked" list is simply:
**all ports that are not shown as allowed or honeypot in `status`.**

To see the active allow/honeypot rules:
```bash
./run.sh status
sudo iptables -L TSUNAMIWALL -n
```

To see which destination ports are being actively dropped/probed recently:
```bash
sudo scripts/tsunamiwall-logs dropped
sudo scripts/tsunamiwall-logs dropped 30   # top 30
sudo dmesg | scripts/extract-attack-ports.sh --dst-port
```

### Inspecting logs with `scripts/tsunamiwall-logs`

The `scripts/tsunamiwall-logs` helper reads the JSONL hit log and the per-country payload tree without needing the daemon socket:

```bash
scripts/tsunamiwall-logs recent             # last 50 hits
scripts/tsunamiwall-logs recent 20          # last 20 hits
scripts/tsunamiwall-logs tail               # follow the hit log live
scripts/tsunamiwall-logs by-ip 1.2.3.4
scripts/tsunamiwall-logs by-country US
scripts/tsunamiwall-logs by-dst 10005
scripts/tsunamiwall-logs payloads 1.2.3.4    # show payloads for an IP
scripts/tsunamiwall-logs stats               # top IPs, countries and ports
scripts/tsunamiwall-logs dropped             # top dropped destination ports
scripts/tsunamiwall-logs recent-payloads     # recent hits with payload previews
scripts/tsunamiwall-logs recent-payloads 10 --bytes 200
```

### Emergency reset
If anything goes wrong, this stops the daemon and flushes every TsunamiWall rule:
```bash
sudo .venv/bin/python main.py reset
# or, if the daemon is dead/stuck:
sudo .venv/bin/python tsunamiwall/emergency.py
```

## How it works
1. The daemon scans `/proc/net/tcp` and `/proc/net/udp` every 30 seconds.
2. By default, any port with a listening socket is allowed through iptables.
3. With `auto_block_listeners: true`, listening sockets are **not** auto-allowed; only explicitly `allow`ed ports are opened.
4. Ports `10000-65535` that are not listening (or not in use in strict mode) are bound by silent asyncio honeypot servers.
5. Ports added via `block` are dropped and logged even if a service listens on them.
6. Each probe to a honeypot port is logged as JSON to `/var/log/tsunamiwall/hits.logl`.
7. Everything else is dropped and logged by iptables.

## Configuration file

TsunamiWall reads YAML configuration from one of these locations, in order:

1. Path given with `--config /path/to/config.yaml`
2. Path in the `TSUNAMIWALL_CONFIG` environment variable
3. `/etc/tsunamiwall/config.yaml`
4. `~/.config/tsunamiwall/config.yaml`

If none exist, built-in defaults are used. See `config/example-config.yaml` for a documented template.

```bash
sudo mkdir -p /etc/tsunamiwall
sudo cp config/example-config.yaml /etc/tsunamiwall/config.yaml
sudoedit /etc/tsunamiwall/config.yaml
sudo .venv/bin/python main.py -c /etc/tsunamiwall/config.yaml start
# or:
./run.sh -c /etc/tsunamiwall/config.yaml start
```

Key tunables:
- `honeypot_start` / `honeypot_end` — honeypot port range.
- `max_honeypots` — hard cap on listeners (default 900, safe for default Linux fd limits).
- `discovery_interval` — how often to re-scan sockets.
- `trusted_ips` — IPs/CIDRs that bypass all filtering. Put your management IP here.
- `auto_block_listeners` — strict default-deny mode; listening sockets are not auto-allowed.
- Runtime `allow`/`deny`/`block` state is persisted to `<run_dir>/daemon-state.json`.

## Using a custom config with the CLI

```bash
sudo .venv/bin/python main.py -c /path/to/config.yaml start
sudo .venv/bin/python main.py -c /path/to/config.yaml status
sudo .venv/bin/python main.py -c /path/to/config.yaml logs
```

## Analyzing drop logs

TsunamiWall logs every dropped packet to the kernel log with the prefix `TSUNAMIWALL-DROP:`. A helper script is provided to extract attacker ports/IPs.

```bash
# Unique attacker source ports
sudo dmesg | ./scripts/extract-attack-ports.sh

# Unique attacker source IPs
sudo dmesg | ./scripts/extract-attack-ports.sh --src-ip

# Unique destination ports the attackers probed
sudo dmesg | ./scripts/extract-attack-ports.sh --dst-port
```
