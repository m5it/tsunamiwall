:tsunami: # TsunamiWall

Linux server firewall with built-in per-port honeypot listeners.

## What it does
- **Blocks** all unsolicited inbound traffic by default.
- **Allows** traffic only to real listening services and explicitly allowed ports.
- **Drops + logs** every unwanted probe.
- **Opens stealth honeypot listeners** on unused high ports (`10000-65535`) to catch and record attacker behavior.
- **Captures attacker payloads** and stores them per country / per IP.
- Provides a simple CLI, a live TUI, config-file support, and an emergency reset for safety.

## Status
v1 focuses on TCP/UDP listening socket discovery, `iptables` (IPv4) backend, optional `ip6tables` (IPv6) support, manual CLI, and honeypot threat visibility.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install -e .

# Optional: offline country lookups for captured payloads
.venv/bin/pip install -r requirements-geoip.txt

# Create a config
sudo mkdir -p /etc/tsunamiwall
sudo cp config/example-config.yaml /etc/tsunamiwall/config.yaml
sudoedit /etc/tsunamiwall/config.yaml

# Start the daemon
sudo .venv/bin/python main.py -c /etc/tsunamiwall/config.yaml start

# In another terminal
.venv/bin/python main.py status
.venv/bin/python main.py watch      # live TUI of honeypot hits
.venv/bin/python main.py logs
```

Or use the convenience wrapper so you don't have to type the full venv path:

```bash
./run.sh -c /etc/tsunamiwall/config.yaml start
./run.sh status
./run.sh watch
./run.sh reset
```

For an all-in-one start, use the included `start.sh` script. It starts the daemon in the background, opens the live TUI, and gracefully stops the daemon when you press `q`:

```bash
./start.sh
# or with a custom config:
./start.sh /etc/tsunamiwall/config.yaml
```

## CLI commands

| Command | Purpose |
|---|---|
| `start` | Run the daemon in the foreground (needs root) |
| `stop` | Gracefully stop the daemon and save runtime state |
| `status` | Show allowed/blocked ports and active honeypots |
| `watch` | Live full-screen TUI of honeypot hits |
| `logs` | Show recent honeypot hits |
| `allow <port>` / `allow --file <path>` | Allow one or many ports |
| `allow <port> --ip <IP/CIDR>` | Allow a port only for a specific source IP or CIDR (persistent) |
| `deny <port>` / `deny --file <path>` | Remove one or many allowed ports |
| `deny <port> --ip <IP/CIDR>` | Remove a per-source-IP allowed port |
| `block <port>` / `block --file <path>` | Block a port (drop traffic even if a service listens) |
| `unblock <port>` / `unblock --file <path>` | Remove a blocked port |
| `reset` | Emergency stop + flush all TsunamiWall `iptables` (and `ip6tables` if enabled) rules |

## Configuration file

TsunamiWall reads YAML configuration from (in order):

1. `--config PATH`
2. `TSUNAMIWALL_CONFIG` environment variable
3. `/etc/tsunamiwall/config.yaml`
4. `~/.config/tsunamiwall/config.yaml`

Key options include `trusted_ips`, `auto_block_listeners`, `honeypot_start`/`honeypot_end`, `max_honeypots`, payload capture settings, log rotation settings, and `enable_ipv6` for dual-stack hosts.

## Architecture

```
+----------+       Unix socket       +----------------------+
|  CLI/TUI |  ---------------------->|  tsunamiwall daemon  |
+----------+                         |  - discovery loop    |
                                     |  - honeypot servers  |
                                     |  - iptables backend  |
                                     +----------+-----------+
                                                |
                                                v
                                     +----------+-----------+
                                     |      iptables        |
                                     |  TSUNAMIWALL chain   |
                                     +----------------------+
```

- **Daemon**: `asyncio`-based, watches listening sockets, manages honeypot listeners.
- **Firewall backend**: `iptables` (IPv4) via a dedicated `TSUNAMIWALL` chain, with optional `ip6tables` (IPv6) support when `enable_ipv6: true`.
- **CLI/TUI**: Unix-socket client talking to the daemon.
- **Payload logging**: captured data is written to `/var/log/tsunamiwall/bycountry/{CC}/{IP}/`.
- **Log viewer script**: `scripts/tsunamiwall-logs` makes it easy to inspect hits and payloads.

## Log viewer

The `scripts/tsunamiwall-logs` script reads the JSONL hit log and the per-country
payload tree without needing the daemon socket:

```bash
scripts/tsunamiwall-logs recent               # last 50 hits
scripts/tsunamiwall-logs recent 20            # last 20 hits
scripts/tsunamiwall-logs tail                 # follow the hit log live
scripts/tsunamiwall-logs by-ip 1.2.3.4
scripts/tsunamiwall-logs by-country US
scripts/tsunamiwall-logs by-dst 10005
scripts/tsunamiwall-logs payloads 1.2.3.4     # show captured payloads for an IP
scripts/tsunamiwall-logs stats                # top IPs, countries and ports
scripts/tsunamiwall-logs dropped              # top dropped destination ports
scripts/tsunamiwall-logs recent-payloads      # recent hits with payload previews
scripts/tsunamiwall-logs recent-payloads 10 --bytes 200
```

## Documentation
- `docs/usage.md` — installation, commands, and tuning.
- `docs/development.md` — project structure and testing.
- `DESIGN.md` — architecture and data flow.
- `AGENTS.md` — agent context and conventions.
- `CHANGELOG.md` — release history.

## License
MIT
