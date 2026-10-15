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
   - trusted source IPs/CIDRs
   - loopback traffic
   - established/related connections
   - ports used by real services
   - honeypot ports (TCP only in v1)
3. Default-drop all other inbound IPv4 traffic.
4. Spawn asyncio TCP honeypot servers on ports `10000-65535` that are not real services.
5. Capture up to `payload_max_bytes` from each honeypot connection and store raw bytes plus metadata under `/var/log/tsunamiwall/bycountry/{CC}/{IP}/`.
6. Offline country-code lookup via optional `iptocc` dependency.
7. CLI commands: `start`, `status`, `watch`, `allow <port>`, `allow --file`, `deny <port>`, `deny --file`, `reset`, `logs`.
8. Live `curses` TUI (`watch`) for real-time honeypot hit monitoring.
9. Config file with `--config PATH` and `TSUNAMIWALL_CONFIG` support.
10. Emergency reset tool clears all TsunamiWall rules even when the daemon is dead.
11. Graceful shutdown with timeouts and hard-exit fallback to avoid hanging on Ctrl+C.

## Data flow
1. On `start`, discovery scans `/proc/net/tcp` and `/proc/net/udp`.
2. iptables rules are written to chain `TSUNAMIWALL`.
3. Honeypot coroutines bind to free ports in the configured range.
4. Every 30 seconds the daemon re-discovers sockets; if a real service appears on a honeypot port, the honeypot is released and iptables updated.
5. CLI commands sent over a Unix socket are handled by the daemon.
6. On a honeypot hit the daemon logs a JSONL hit line, reads an optional payload, resolves the country code, and writes the payload to `bycountry/{CC}/{IP}/{timestamp}_{dst_port}.bin` plus a `sessions.logl` metadata file.

## Threat log format
Each honeypot hit creates a JSON line:
```json
{"time":"2026-10-11T12:34:56Z","src_ip":"1.2.3.4","src_port":54321,"dst_port":12345,"proto":"tcp","action":"honeypot_hit"}
```
Logs are written to `/var/log/tsunamiwall/hits.logl`.

## Payload log format
Each honeypot probe that sends data creates:
- A raw binary file: `/var/log/tsunamiwall/bycountry/{CC}/{IP}/{time}_{dst_port}.bin`
- A metadata JSONL file: `/var/log/tsunamiwall/bycountry/{CC}/{IP}/sessions.logl`

Metadata line example:
```json
{"time":"2026-10-11T12:34:56Z","src_ip":"1.2.3.4","src_port":54321,"dst_port":12345,"country":"US","payload_bytes":42,"payload_file":"/var/log/tsunamiwall/bycountry/US/1.2.3.4/2026-10-11T12-34-56Z_12345.bin"}
```

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
- `run_dir = "/run/tsunamiwall"` — `daemon.sock` and `daemon.pid` are derived from this directory
- `max_honeypots = 900`
- `trusted_ips = []` — source IPs/CIDRs allowed before any port filtering
- `payload_max_bytes = 4096`
- `payload_read_timeout = 2.0`
- `payload_log_dir = "/var/log/tsunamiwall/bycountry"`
