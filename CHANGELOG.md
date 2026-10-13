# Changelog

All notable changes to TsunamiWall are documented in this file.

## [Unreleased] - current

### Added
- **Core daemon** — asyncio-based daemon that scans listening sockets every 30 seconds and reconciles `iptables` rules + honeypot listeners.
- **iptables backend** — all TsunamiWall rules live in a dedicated `TSUNAMIWALL` chain jumped from `INPUT`. Supports loopback, established/related, per-source-IP ports, real service ports, honeypot ports, drop + log.
- **Honeypot listeners** — silent TCP listeners on unused high ports (`10000-65535`, max 900 by default). Each connection is logged as JSON to `/var/log/tsunamiwall/hits.logl`.
- **CLI** — `start`, `status`, `logs`, `allow`, `deny`, `reset`, plus `--config`/`-c` support.
- **Config file** — YAML config loaded from `--config`, `TSUNAMIWALL_CONFIG`, `/etc/tsunamiwall/config.yaml`, or `~/.config/tsunamiwall/config.yaml`.
- **Trusted IPs** — `trusted_ips` list allows selected source IPs/CIDRs to bypass all filtering.
- **Per-IP allow/deny** — `allow <port> --ip <IP/CIDR>` and `deny <port> --ip <IP/CIDR>` restrict ports to a single source address or network.
- **Port files** — `allow --file` and `deny --file` accept a text file with one port per line.
- **Emergency reset** — `reset` command falls back to a direct iptables flush if the daemon is not reachable.
- **Live TUI** — `watch` subcommand opens a `curses` full-screen table of honeypot hits in real time.
- **Payload capture + country grouping** — reads up to `payload_max_bytes` from each probe and writes raw bytes plus metadata to `/var/log/tsunamiwall/bycountry/{CC}/{IP}/`.
- **Offline country lookup** — optional `iptocc` integration resolves attacker country codes without external APIs or databases.
- **Convenience wrappers** — `run.sh` and `run-dev.sh` run TsunamiWall as root using the local `.venv` Python.
- **Log analysis scripts** — `scripts/extract-attack-ports.sh` extracts unique source ports/IPs/destination ports from `dmesg` drop logs; `scripts/tsunamiwall-logs` provides a friendly CLI to inspect hits and payloads.
- **Tests** — pytest suite covering config, discovery, honeypot, iptables, CLI, TUI, trusted IPs, payload logging, per-IP allow rules, log viewer, and reset fallback.

### Fixed
- **Graceful shutdown** — added timeouts to daemon stop, honeypot teardown, and iptables commands; falls back to hard exit after 10 seconds if shutdown hangs.
- **Reset against dead daemon** — `reset` now correctly falls back to emergency flush when the daemon socket exists but no process is listening.

## v0.1.0 - initial scaffold

- Project created with package structure, `pyproject.toml`, and basic documentation.
