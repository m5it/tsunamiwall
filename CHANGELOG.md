# Changelog

All notable changes to TsunamiWall are documented in this file.

## [Unreleased] - current

## [1.2.0] - 2026-10-16

### Added
- **macOS / pfctl firewall backend** — new `firewall_backend` config option. On macOS TsunamiWall can use the native `pfctl` anchor mechanism instead of `iptables`. Linux still defaults to `iptables`/`ip6tables`.
- **Cross-platform service discovery** — socket discovery now prefers `psutil` when `/proc/net/tcp` and `/proc/net/udp` are unavailable (e.g. macOS).
- **No-op backend** — `firewall_backend: noop` disables firewall rule management for testing or unsupported platforms.
- **Per-hit IP family + payload size** — honeypot hit logs now include `family` (`ipv4` or `ipv6`) and `payload_size` fields so logs, the live TUI, and `tsunamiwall-logs` can distinguish IPv4/IPv6 probes and show whether a payload was captured without needing to read disk.

### Fixed
- **Linux startup file-descriptor exhaustion** — honeypot listeners now bind to `0.0.0.0` (IPv4 only) instead of dual-stack. This halves socket usage and prevents `OSError: Too many open files` during firewall rule generation when `max_honeypots` is near the default file-descriptor limit.
- **Unique payload filenames** — payload files are now named with a nanosecond-resolution timestamp + destination port + source port so multiple probes from the same IP in the same second never overwrite each other.
- **Accurate payload matching in log viewer** — `tsunamiwall-logs recent-payloads` now matches files by `dst_port` + `src_port` and picks the file whose mtime is closest to the hit time, instead of guessing by date prefix.
- **Payload write error handling** — the daemon now logs `PermissionError` and other payload-write exceptions instead of silently dropping captured bytes.
- **Truly atomic iptables cutover** — the shadow chain jump is now inserted into `INPUT` *before* the old chain jump is removed, so there is never a gap where packets bypass TsunamiWall. Chain renames then give the active ruleset the configured name. If a rename fails, the previous ruleset is restored under the configured chain name.

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
