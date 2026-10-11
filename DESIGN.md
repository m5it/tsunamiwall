# TsunamiWall Design Document

## Overview
TsunamiWall is a Linux server firewall that combines strict default-deny packet filtering with per-port honeypot listeners for threat visibility.

## Terminology
- **Real service**: a process currently listening on a TCP or UDP port that the administrator wants to keep reachable.
- **Honeypot port**: an unused port where TsunamiWall binds a fake listener to log probes.
- **Managed port**: either a real service port (allowed through iptables) or a honeypot port (allowed and listened on).

## v1 features
1. Discover listening IPv4 TCP/UDP sockets.
2. Build iptables allowlist:
   - loopback traffic
   - established/related connections
   - ports used by real services
   - honeypot ports (TCP only in v1)
3. Default-drop all other inbound IPv4 traffic.
4. Spawn asyncio TCP honeypot servers on ports `10000-65535` that are not real services.
5. CLI commands: `start`, `stop`, `status`, `allow <port>`, `deny <port>`, `reset`, `logs`.
6. Emergency reset tool clears all TsunamiWall rules and stops honeypots.

## Data flow
1. On `start`, discovery scans `/proc/net/tcp` and `/proc/net/udp`.
2. iptables rules are written to chain `TSUNAMIWALL`.
3. Honeypot coroutines bind to free ports in the configured range.
4. Every 30 seconds the daemon re-discovers sockets; if a real service appears on a honeypot port, the honeypot is released and iptables updated.
5. CLI commands sent over a Unix socket are handled by the daemon.

## Threat log format
Each honeypot hit creates a JSON line:
```json
{"time":"2026-10-11T12:34:56Z","src_ip":"1.2.3.4","src_port":54321,"dst_port":12345,"proto":"tcp","action":"honeypot_hit"}
```
Logs are written to `/var/log/tsunamiwall/hits.logl`.

## Configuration

Config is loaded from YAML in this precedence:
1. `--config PATH` CLI argument
2. `TSUNAMIWALL_CONFIG` environment variable
3. `/etc/tsunamiwall/config.yaml`
4. `~/.config/tsunamiwall/config.yaml`
5. Built-in defaults

Key values:
- `honeypot_start = 10000`
- `honeypot_end = 65535`
- `discovery_interval = 30` seconds
- `iptables_chain = "TSUNAMIWALL"`
- `log_dir = "/var/log/tsunamiwall"`
- `run_dir = "/run/tsunamiwall"`
- `socket_path = "/run/tsunamiwall/daemon.sock"`
- `max_honeypots = 900`
- `trusted_ips = []` — source IPs/CIDRs allowed before any port filtering
