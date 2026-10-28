# Changelog

All notable changes to TsunamiWall are documented in this file.

## [Unreleased] - current

### Added

### Fixed

## [1.3.2] - 2026-10-29

### Added
- **Hit log archival into .tar.gz** — when `hits.logl` exceeds the new `hit_log_archive_max_hits` threshold (default 100 000 entries), the daemon merges the log's aggregate statistics into a persistent `hits-stats.json` file, compresses the log into a dated `.tar.gz` under `log_dir/archives/`, and starts a fresh `hits.logl`. This keeps `--stats` and `--recent` fast even after hundreds of thousands of hits.
- **`hit_log_archive_max_hits` config option** — controls how many unpacked hit records are kept before automatic archival.
- **`hit_log_archive_dir` config option** — optionally overrides the archive directory; defaults to `<log_dir>/archives/`.
- **`tsunamiwall-logs --archive`** — manually triggers the same archive+stats-merge operation that the daemon performs automatically.
- **`tsunamiwall-logs --stats` merges archived statistics** — by default, statistics now combine the persistent `hits-stats.json` (all-time archived totals) with the current unpacked `hits.logl`, so you see totals from the beginning, not just the latest window.
- **`tsunamiwall-logs --stats --all-time`** — also scans every archived `.tar.gz` to produce complete all-time statistics. This is slower but fully accurate.

## [1.3.1] - 2026-10-23

### Fixed
- Bumped package version to 1.3.1.

## [1.3.0] - 2026-10-23

### Added
- **Version flag for log viewer** — `scripts/tsunamiwall-logs --version` / `-v` now prints the package version.
- **Date filter for log viewer** — `scripts/tsunamiwall-logs` now supports `--date YYYY-MM-DD` to restrict `--stats`, `--recent`, `--recent-payloads`, `--tail` and `--payloads` to a single calendar day.

### Changed
- **Argument-based log viewer CLI** — `scripts/tsunamiwall-logs` now uses flags instead of sub-commands: `--recent`/`-r`, `--tail`/`-t`, `--stats`/`-s`, `--dropped`/`-d`, `--payloads`/`-p`, `--recent-payloads`/`-P`. Shared filters `--ip`/`-i`, `--country`/`-C`, `--src-port`/`-S`, `--dst-port`/`-D`, `--date`, `--last`/`-n` and `--bytes`/`-b` work across all viewing modes. The previous sub-command syntax (e.g. `tsunamiwall-logs recent 20`, `tsunamiwall-logs by-ip 1.2.3.4`) is automatically translated for backward compatibility.

### Fixed
- **Log viewer ordering** — `recent`, `by-ip`, `by-country`, `by-dst` and `recent-payloads` now display hits newest-first (descending) instead of file-order.
- **`tail` follows log rotation** — `scripts/tsunamiwall-logs tail` now detects when `hits.logl` is rotated and reopens the current file, so it no longer gets stuck on an old inode and misses new honeypot hits.
- **Consistent log viewer time display** — hit times are now converted from UTC to local time before printing, so `tail`/`recent` timestamps match the payload mtime display and `date`.
- **Hit-log backup cap enforced** — `rotate_hit_log` now deletes backup files beyond `hit_log_max_backups`, so repeated rotations can no longer fill the disk.
- **Quoted boolean config values parsed correctly** — boolean fields such as `enable_ipv6: "false"` and `auto_block_listeners: "true"` are now parsed as real booleans instead of being truthy strings. Invalid strings (e.g. `"yes"`) raise a clear `ValueError`.
- **Cross-platform service discovery** — socket discovery now prefers `psutil` when `/proc/net/tcp` and `/proc/net/udp` are unavailable (e.g. macOS).
- **No-op backend** — `firewall_backend: noop` disables firewall rule management for testing or unsupported platforms.
- **Per-hit IP family + payload size** — honeypot hit logs now include `family` (`ipv4` or `ipv6`) and `payload_size` fields so logs, the live TUI, and `tsunamiwall-logs` can distinguish IPv4/IPv6 probes and show whether a payload was captured without needing to read disk.
- **Configurable low-port honeypots** — the honeypot port range (`honeypot_start`/`honeypot_end`) can now be set as low as port 1. The daemon runs as root and can bind privileged ports; a warning is logged when a honeypot binds to a port below 1024.
- **Status shows active config + config path** — `./run.sh status` now reports the full configuration the daemon is running with and the path of the config file it loaded, so it is easy to verify which file is in use.
- **Firewall jump detection and reset hardening** — `_install_jump_if_missing()` now uses `iptables -C` / `ip6tables -C` instead of parsing `iptables -L` output for `-j CHAIN`, which could miss existing jumps and insert duplicates during rollback. `reset()` now removes all jumps to the configured chain and deletes leftover `_NEW` and `_OLD` shadow/rollback chains, so a failed atomic swap cannot leave stale rules or references behind.
- **Family-aware discovery helpers** — added `discover_ports_by_family()` to return `{ipv4, ipv6}` port sets independently. `discover_ports()` continues to return the mirrored union used by the daemon. The psutil fallback for IPv4 now uses `kind='inet4'` so IPv6 sockets are not mixed into the IPv4 set on macOS.
- **Discovered real-service ports mirrored across IPv4 and IPv6** — `_reconcile()` intentionally allows a discovered service port on both address families, matching the common dual-stack pattern and keeping the rulesets consistent. This policy is now documented in `AGENTS.md` and tested. Strict per-family allow lists remain possible via `discover_ports_by_family()` for a future configuration option.
- **Network-namespace integration tests** — added `tests/test_netns_firewall.py` and `tests/test_netns_daemon.py`. They run real `iptables`/`ip6tables` and a real daemon inside isolated Linux network namespaces, validating rule installation, reset, restart, and IPv6 startup-failure rollback. They skip automatically when namespaces are unavailable.
- **IPv6-only services discovered when IPv6 is enabled** — `_reconcile()` now asks `discover_ports()` for IPv6 listeners whenever `enable_ipv6: true` or `firewall_backend: ip6tables`. `/proc/net/tcp6` and `/proc/net/udp6` are now parsed directly on Linux; addresses are decoded by reversing each 32-bit host-order word so `::1` no longer becomes `100::`. `/proc/net/udp`/UDP6 filtering correctly skips connected UDP sockets.
- **Explicit IPv6-only backend routing** — `firewall_backend: "ip6tables"` now runs a true IPv6-only deployment: the daemon builds a single IPv6 ruleset, IPv4 is not managed, and shutdown/emergency reset target the IPv6 chain directly. `firewall_backend: "iptables"` continues to manage IPv4 and, when `enable_ipv6: true`, a separate IPv6 chain.
- **IPv6 firewall setup failure fails startup and rolls back** — when `enable_ipv6: true`, a failure to install the IPv6 ruleset during daemon startup now raises and fails `start()` instead of being logged and ignored. `start()` catches the failure and runs the same `stop()` cleanup path, removing the PID file, stopping any honeypots, and resetting both the primary and IPv6 firewall chains so partial rules are not left behind. Periodic reconcile failures after startup are still logged and tolerated so working IPv4 protection is not torn down.
- **Consistent UDP service discovery** — `/proc/net/udp` parsing now only reports bound/listening UDP sockets (those with a zeroed remote address `00000000:0000`). Connected UDP sockets are no longer misreported as listeners. The psutil fallback now accepts UDP sockets in `CONN_NONE` state in addition to `CONN_LISTEN`, matching how psutil reports connectionless UDP sockets on macOS and Linux.
- **Accurate payload matching in log viewer** — `tsunamiwall-logs recent-payloads` now matches files by `dst_port` + `src_port` and picks the file whose mtime is closest to the hit time, instead of guessing by date prefix.
- **Payload write error handling** — the daemon now logs `PermissionError` and other payload-write exceptions instead of silently dropping captured bytes.
- **Truly atomic iptables cutover** — the shadow chain jump is now inserted into `INPUT` *before* the old chain jump is removed, so there is never a gap where packets bypass TsunamiWall. Chain renames then give the active ruleset the configured name. If a rename fails, the previous ruleset is restored under the configured chain name.
- **run.sh defaults to the caller's config** — when `run.sh` is invoked without `-c`/`--config`, it now defaults to the caller's own `~/.config/tsunamiwall/config.yaml` before elevating with `sudo`. This prevents `sudo` from changing `$HOME` to `/root` and loading a different config file than the user expects.
- **Graceful stop with stale socket** — `tsunamiwall stop` now catches `DaemonUnreachable` when the socket file exists but no daemon is listening, removes the stale socket, and reports the situation cleanly instead of crashing with a traceback.
- **Clearer YAML parse errors** — invalid YAML in a config file now produces a readable `ValueError` instead of a raw PyYAML traceback.

## [1.1.0] - 2026-10-16

### Fixed
- **Signal shutdown cleanup** — SIGTERM/Ctrl+C now route through the same `stop()` cleanup path as the CLI `stop` command, so firewall rules are flushed, state is saved, and the PID file is removed.
- **Derived run-time paths** — `socket_path` and `pid_path` are now derived from `run_dir` instead of being independent config options. Old configs that still contain them are accepted but ignored.
- **Global `block` precedence** — a globally `block`ed port now overrides auto-discovered services, explicit `allow` rules, and per-source-IP `allow` rules. Blocked ports are also excluded from the honeypot pool.
- **Atomic iptables rule updates** — `build_rules` now builds a fresh shadow chain and swaps it in, so packets never pass through a partially-built or flushed-empty chain. On failure it rolls back to the previous ruleset.
- **Daemon error response type** — `_error()` and `_handle_client()` now return/emit JSON `dict`s instead of pre-encoded JSON strings, so the CLI can safely call `.get()` on every response. Invalid ports and unknown actions no longer crash the client.
- **Emergency reset honors custom config** — `emergency_reset()` now accepts a config object and uses its `iptables_chain` and `run_dir`. `cmd_reset` passes the loaded config through, so a custom chain is properly flushed when the daemon is unreachable.
- **Payload file uniqueness + empty-payload skip** — payload filenames now include sub-second microsecond precision and source port, so rapid probes from the same IP no longer overwrite each other. Empty/timed-out payloads are no longer written to disk or metadata; they remain visible in the hit log only.

### Added
- **Log rotation** — `hits.logl` is rotated when it exceeds `hit_log_max_bytes` (default 100 MiB); up to `hit_log_max_backups` old files are kept.
- **Payload retention cap** — `cleanup_payloads` removes oldest `.bin` files when total payload storage exceeds `payload_log_max_bytes` (default 1 GiB). Metadata `sessions.logl` files are preserved.
- **Rate-limited firewall logging** — all iptables `LOG` rules use `-m limit` with configurable `log_rate_limit` / `log_rate_burst` to prevent `dmesg`/journal flooding under heavy scans.
- New module `tsunamiwall/rotation.py` and tests `tests/test_rotation.py`, `tests/test_rate_limited_logging.py`.
- **IPv6 support** — new `enable_ipv6: true` config option. When enabled, TsunamiWall also manages an `ip6tables` chain with the same policy as IPv4, and honeypots bind to all addresses. By default only IPv4 is protected and IPv6 traffic is left untouched; this is now explicitly documented.
- **CLI `allow --ip`** — per-source-IP allow rules via `tsunamiwall allow <port> --ip <IP/CIDR>` and matching `deny --ip` removal.
- **CLI response robustness** — `cmd_status` now catches socket errors and prints a clear message when the daemon is unreachable.
- **Per-IP allow persistence** — per-source-IP allow rules are included in `daemon-state.json` and restored on startup.

## [1.0.0] - 2026-10-11

Initial release.
