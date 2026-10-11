# TsunamiWall Usage

## Requirements
- Linux server with Python 3.10+
- root privileges (for iptables and raw socket binding)
- `iptables` installed

## Installation

```bash
pip install -e .
```

This installs two commands: `tsunamiwall` and `tsunamiwall-reset`.

## Important safety note
**Test on a non-production system first.** TsunamiWall changes your iptables `INPUT` chain and drops all unexpected inbound traffic. Make sure you have console access or a way to recover if you lock yourself out.

## Commands

### Start the daemon
```bash
sudo tsunamiwall start
```
Runs in the foreground. Use systemd, supervisord, or `nohup`/`screen` to run it as a service.

### Show current state
```bash
sudo tsunamiwall status
```

### Explicitly allow a port
If you want to keep a port reachable even when nothing is currently listening, or just prefer manual control:
```bash
sudo tsunamiwall allow 8080
```

### Remove an allowed port
```bash
sudo tsunamiwall deny 8080
```

### View honeypot hits
```bash
sudo tsunamiwall logs
```

### Emergency reset
If anything goes wrong, this stops the daemon and flushes every TsunamiWall rule:
```bash
sudo tsunamiwall reset
# or, if the daemon is dead/stuck:
sudo tsunamiwall-reset
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
sudo tsunamiwall start
```

Key tunables:
- `honeypot_start` / `honeypot_end` — honeypot port range.
- `max_honeypots` — hard cap on listeners (default 900, safe for default Linux fd limits).
- `discovery_interval` — how often to re-scan sockets.

## Using a custom config with the CLI

```bash
sudo tsunamiwall -c /path/to/config.yaml start
sudo tsunamiwall -c /path/to/config.yaml status
sudo tsunamiwall -c /path/to/config.yaml logs
```
