# TsunamiWall — Agent Notes

This file is the canonical project context for coding agents. If you pick up this project, read this first, then `DESIGN.md` and `docs/development.md`.

## Project goal
Build a server firewall with three jobs:
1. Block all unwanted inbound traffic.
2. Run stealth honeypot listeners on unused high ports to log what attackers/scanners are probing.
3. Support per-source-IP port rules for fine-grained access.

## Current status
Active development. Core daemon runs on real servers, manages iptables, opens honeypots, and already catches live internet scans. See `CHANGELOG.md` for the latest feature list.

## v1 scope
- Target environment: servers.
- Packet filter backend: pluggable; `iptables` (IPv4) / `ip6tables` (IPv6) on Linux, `pfctl` anchors on macOS, plus a `noop` backend for testing.
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
- `tsunamiwall/firewall.py` — pluggable firewall backend abstraction (`iptables`, `ip6tables`, `pfctl`, `noop`).
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
- `reset` first tries to talk to the daemon; if the socket is dead it falls back to the configured firewall backend.
- `daemon.sock` and `daemon.pid` are derived from `run_dir`; do not set `socket_path` or `pid_path` independently.
- All TsunamiWall rules live in a dedicated `TSUNAMIWALL` chain jumped from `INPUT` (Linux) or in the configured `pfctl` anchor (macOS). Do not modify pre-existing rules.
- The default honeypot range starts at 10000 to avoid common system services. Lower ports are allowed when explicitly configured; the daemon runs as root and can bind privileged ports, but you must verify that no real service is listening on those ports.
- The daemon must detect new real services and immediately release conflicting honeypots.
- Runtime allow/block/deny state is persisted to `<run_dir>/daemon-state.json` and restored on startup.
- The hit log is archived when it exceeds `hit_log_archive_max_hits` entries (default 100 000): aggregate statistics are merged into `<log_dir>/hits-stats.json`, the log is compressed into a dated `.tar.gz` under `<log_dir>/archives/`, and a fresh `hits.logl` is started. This keeps `tsunamiwall-logs --stats` and `--recent` fast on very busy honeypots. Use `--stats --all-time` to also scan every archive, or `--list-archives` / `--open-archive` / `--close-archive` to inspect individual archived packages.
- `auto_block_listeners: true` switches the daemon to strict default-deny: discovered listening sockets are not automatically allowed. The default is `false`, meaning every discovered listener is automatically allowed; this is convenient but not a strict default-deny policy.
- A globally `block`ed port overrides `allow`, per-source-IP `allow`, auto-discovered services, and honeypot selection. `trusted_ips` still bypass the block.
- Set `enable_ipv6: true` in config to also manage an `ip6tables` chain with the same default-deny policy for real services and per-IP rules. By default only IPv4 is protected; IPv6 traffic is left untouched. Honeypots bind to `0.0.0.0` (IPv4 only) to avoid file-descriptor exhaustion, so honeypot ports are not opened in the IPv6 chain.
- `firewall_backend: "iptables"` (default) manages the IPv4 chain; if `enable_ipv6` is true it also manages a separate IPv6 chain. `firewall_backend: "ip6tables"` runs an IPv6-only deployment where IPv4 is not managed at all. This is useful for hosts that only need IPv6 protection.
- **Discovered real-service ports are mirrored across IPv4 and IPv6.** A port listening on only one family is still allowed on both, matching the common dual-stack pattern and keeping the two rulesets consistent. `discover_ports_by_family()` is available for callers that need strict per-family allow lists in the future.
- Set `firewall_backend: "pfctl"` on macOS to use `pfctl` anchors. The base anchor (default `tsunamiwall`) must be referenced in `/etc/pf.conf` by the user; TsunamiWall only manages the sub-anchor contents.
- Service discovery falls back to `psutil` when `/proc/net/tcp` and `/proc/net/udp` are unavailable (e.g. macOS).

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
- All firewall interactions go through `tsunamiwall/firewall.py`. Low-level `iptables` helpers live in `tsunamiwall/iptables.py` and `tsunamiwall/ip6tables.py`; `pfctl` logic lives in the `PfctlBackend` class.
- All new config keys go into `tsunamiwall/config.py` and `config/example-config.yaml`.
- Prefer `asyncio` for network-facing code.
- Never mutate pre-existing firewall rules outside the TsunamiWall-managed chain or anchor.
- Update `CHANGELOG.md`, `README.md`, and this file when adding user-facing features or changing run behavior.
