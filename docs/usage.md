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

### Remove an allowed port
```bash
sudo .venv/bin/python main.py deny 8080
```

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

### Emergency reset
If anything goes wrong, this stops the daemon and flushes every TsunamiWall rule:
```bash
sudo .venv/bin/python main.py reset
# or, if the daemon is dead/stuck:
sudo .venv/bin/python tsunamiwall/emergency.py
```

## How it works
1. The daemon scans `/proc/net/tcp` and `/proc/net/udp` every 30 seconds.
2. Any port with a listening socket is allowed through iptables.
3. Ports `10000-65535` that are not listening are bound by silent asyncio honeypot servers.
4. Each probe to a honeypot port is logged as JSON to `/var/log/tsunamiwall/hits.logl`.
5. Everything else is dropped and logged by iptables.

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
