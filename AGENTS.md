# TsunamiWall — Agent Notes

This file is the canonical project context for coding agents. If you pick up this project, read this first, then `DESIGN.md` and `docs/development.md`.

## Project goal
Build a Linux server firewall with three jobs:
1. Block all unwanted inbound traffic.
2. Run stealth honeypot listeners on unused high ports to log what attackers/scanners are probing.
3. Support per-source-IP port rules for fine-grained access.

## Current status
Active development. Core daemon runs on real servers, manages iptables, opens honeypots, and already catches live internet scans. See `CHANGELOG.md` for the latest feature list.

## v1 scope
- Target environment: servers.
- Packet filter backend: `iptables` (IPv4) with optional `ip6tables` support for dual-stack hosts.
- Service discovery: listening sockets only (read from `/proc/net/tcp`, `/proc/net/udp`, `ss`, and `psutil` if available).
- Management interface: manual CLI plus live TUI.
- Honeypot scope: ports `10000-65535`, excluding ports already used by real services.
- Honeypot behavior: accept connections, optionally read a small payload, log metadata, store payload by country/IP, then close.
- Safety: emergency `reset` flushes all TsunamiWall-managed iptables and (if enabled) ip6tables rules even if the daemon is dead.

## Architecture

```
+----------------------------------+
|  tsunamiwall daemon (asyncio)    |
|  - listens on CLI unix socket    |
|  - scans listening sockets         |
|  - manages honeypot coroutines     |
|  - writes iptables rules           |
|  - logs hits + payloads            |
+----------------------------------+
                |
                v
+----------------------------------+
|  iptables                        |
|  - default DROP for INPUT        |
|  - allow trusted source IPs      |
|  - allow loopback                |
|  - allow established/related     |
|  - allow per-source-IP ports     |
|  - allow real service ports      |
|  - allow honeypot ports          |
|  - log + drop everything else    |
+----------------------------------+
```

## Key modules
- `tsunamiwall/config.py` — configuration, defaults, paths, YAML config file loading.
- `tsunamiwall/discovery.py` — find listening TCP/UDP sockets and their ports.
- `tsunamiwall/geoip.py` — offline country-code lookup (`iptocc`, optional).
- `tsunamiwall/iptables.py` — safe wrapper around `iptables` with timeouts.
- `tsunamiwall/ip6tables.py` — safe wrapper around `ip6tables` for IPv6 support.
- `tsunamiwall/honeypot.py` — asyncio honeypot listener per port, payload capture.
- `tsunamiwall/daemon.py` — main asyncio daemon.
- `tsunamiwall/cli.py` — CLI client talking to the daemon via Unix socket; supports global and per-source-IP allow/deny.
- `tsunamiwall/tui.py` — live `curses` honeypot-hit monitor.
- `tsunamiwall/emergency.py` — standalone reset tool.
- `scripts/tsunamiwall-logs` — friendly log/payload viewer (hits, stats, tail, by-IP, by-country, by-port, payloads, payload previews inline with recent hits, dropped destination ports).

## Important behavioral notes
- `sudo` does **not** see the user's `.venv`. Always run with the absolute venv path or use `run.sh` / `run-dev.sh`.
- The daemon must run as root (iptables + low port binding not needed, but raw sockets and log dirs do).
- Ctrl+C / SIGTERM now route through the same `stop()` cleanup path as the CLI `stop` command, flushing rules, saving state, and removing the PID file. The daemon still has a 10-second graceful shutdown with hard `_exit()` fallback.
- `reset` first tries to talk to the daemon; if the socket is dead it falls back to direct iptables flush.
- `daemon.sock` and `daemon.pid` are derived from `run_dir`; do not set `socket_path` or `pid_path` independently.
- All TsunamiWall rules live in a dedicated `TSUNAMIWALL` chain jumped from `INPUT`. Do not modify pre-existing rules.
- Do not bind honeypots to ports below 10000 to avoid stealing system services.
- The daemon must detect new real services and immediately release conflicting honeypots.
- Runtime allow/block/deny state is persisted to `<run_dir>/daemon-state.json` and restored on startup.
- `auto_block_listeners: true` switches the daemon to strict default-deny: discovered listening sockets are not automatically allowed. The default is `false`, meaning every discovered listener is automatically allowed; this is convenient but not a strict default-deny policy.
- A globally `block`ed port overrides `allow`, per-source-IP `allow`, auto-discovered services, and honeypot selection. `trusted_ips` still bypass the block.
- Set `enable_ipv6: true` in config to also manage an `ip6tables` chain. By default only IPv4 is protected; IPv6 traffic is left untouched. Honeypots bind to all addresses when IPv6 is enabled, otherwise only IPv4.

## Running locally
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install -e .
.venv/bin/python -m pytest

# Run daemon (needs root)
sudo .venv/bin/python main.py -c /etc/tsunamiwall/config.yaml start

# Or use the wrapper
./run.sh -c /etc/tsunamiwall/config.yaml start
```

## Testing
- Run `.venv/bin/python -m pytest`.
- Integration tests requiring root/iptables are skipped automatically.
- Prefer adding pure-logic unit tests; avoid root-only tests unless clearly marked and skippable.

## Coding rules
- Keep changes minimal and focused.
- All iptables interactions go through `tsunamiwall/iptables.py`; IPv6 goes through `tsunamiwall/ip6tables.py`.
- All new config keys go into `tsunamiwall/config.py` and `config/example-config.yaml`.
- Prefer `asyncio` for network-facing code.
- Never mutate pre-existing iptables rules outside the `TSUNAMIWALL` chain.
- Update `CHANGELOG.md`, `README.md`, and this file when adding user-facing features or changing run behavior.
