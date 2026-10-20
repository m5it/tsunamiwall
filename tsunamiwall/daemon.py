"""Asyncio daemon for TsunamiWall."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Any

from .config import Config, default_config, safe_ports
from .discovery import discover_ports, discover_ports_by_family
from .firewall import get_backend
from .honeypot import (
    HitEvent,
    HoneypotServer,
    default_payload_writer,
    jsonl_formatter,
)
from .rotation import cleanup_payloads, rotate_hit_log

logger = logging.getLogger("tsunamiwall.daemon")


class Daemon:
    """Main TsunamiWall daemon."""

    def __init__(self, cfg: Config | None = None, *, config_path: str | None = None):
        self.cfg = cfg or default_config()
        self.config_path = config_path
        self.honeypots: dict[int, HoneypotServer] = {}
        self.allowed_ports: set[int] = set()
        self.allowed_per_ip: dict[str, set[int]] = {}
        self.blocked_ports: set[int] = set()
        self._stop_event = asyncio.Event()
        self._stop_lock = asyncio.Lock()
        self._cleanup_done = asyncio.Event()
        self._server: asyncio.Server | None = None
        self._hit_log_fh = self._open_hit_log()
        self._payload_writer = default_payload_writer(self.cfg)
        # Tracks whether the current _reconcile() is the initial one during
        # daemon startup. IPv6 rule failures during startup are fatal; failures
        # during periodic reconciles are logged but tolerated.
        self._startup_phase = True
        # Firewall backends. The primary backend is always created. The IPv6
        # backend is only created when enable_ipv6 is true, except when the
        # user explicitly selects the ip6tables-only backend, in which case
        # the primary backend is ip6tables and no separate IPv4 backend is run.
        if self.cfg.firewall_backend == "ip6tables":
            self._firewall = get_backend(self.cfg, family="ipv6")
            self._firewall_ipv6 = None
        else:
            self._firewall = get_backend(self.cfg, family="ipv4")
            self._firewall_ipv6 = get_backend(self.cfg, family="ipv6") if self.cfg.enable_ipv6 else None
        self._load_state()

    def _open_hit_log(self):
        os.makedirs(self.cfg.log_dir, exist_ok=True, mode=0o750)
        rotate_hit_log(
            self.cfg.hit_log_path,
            self.cfg.hit_log_max_bytes,
            self.cfg.hit_log_max_backups,
        )
        return open(self.cfg.hit_log_path, "a", encoding="utf-8", buffering=1)

    def _log_hit(self, event: HitEvent) -> None:
        line = jsonl_formatter(event)
        self._hit_log_fh.write(line + "\n")
        self._hit_log_fh.flush()
        logger.info("Honeypot hit: %s", line)


    def _payload_callback(self, session) -> None:
        """Write a captured payload to disk.

        Payload retention cleanup is performed periodically by the discovery
        loop so that a large archive cannot block the event loop on every hit.
        """
        try:
            self._payload_writer(session)
        except PermissionError as exc:
            logger.warning(
                "Cannot write payload for %s:%d to %s: %s",
                session.src_ip,
                session.src_port,
                self.cfg.payload_log_dir,
                exc,
            )
        except Exception:
            logger.exception(
                "Payload write failed for %s:%d",
                session.src_ip,
                session.src_port,
            )

    async def start(self) -> None:
        os.makedirs(self.cfg.run_dir, exist_ok=True, mode=0o750)
        self._ensure_single_instance()
        self._write_pid()

        # Initial discovery and firewall setup.
        try:
            await self._reconcile()
        except Exception:
            logger.exception("Initial reconcile failed; rolling back")
            await self.stop()
            raise
        finally:
            self._startup_phase = False

        # Background tasks.
        self._tasks = [
            asyncio.create_task(self._discovery_loop()),
            asyncio.create_task(self._unix_socket_server()),
        ]

        # Signal handling.
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(sig, self._request_stop)

        logger.info("TsunamiWall daemon started")
        await self._stop_event.wait()
        # Run the same cleanup path regardless of why we woke up (CLI stop, reset,
        # or SIGTERM/Ctrl+C). stop() is idempotent so a CLI-initiated stop does not
        # run twice.
        await self.stop()

    def _ensure_single_instance(self) -> None:
        """Exit if another daemon is already running; otherwise clean up stale pid file."""
        pid_path = Path(self.cfg.pid_path)
        if pid_path.exists():
            try:
                old_pid = int(pid_path.read_text(encoding="utf-8").strip())
            except Exception:
                old_pid = None
            if old_pid is not None and old_pid != os.getpid():
                try:
                    os.kill(old_pid, 0)
                    logger.error("Another TsunamiWall daemon is already running (PID %d). Exiting.", old_pid)
                    sys.exit(1)
                except (ProcessLookupError, PermissionError):
                    pass
            # Stale pid file; remove it so we can write our own.
            try:
                pid_path.unlink()
            except FileNotFoundError:
                pass

    def _write_pid(self) -> None:
        Path(self.cfg.pid_path).write_text(str(os.getpid()), encoding="utf-8")

    def _remove_pid(self) -> None:
        try:
            os.remove(self.cfg.pid_path)
        except FileNotFoundError:
            pass

    def _request_stop(self) -> None:
        logger.info("Shutdown signal received")
        self._stop_event.set()
        # Cleanup is performed by start() after it wakes from the stop event.
        # Schedule a hard exit if graceful shutdown takes too long.
        try:
            loop = asyncio.get_running_loop()
            loop.call_later(10.0, self._hard_exit)
        except RuntimeError:
            # No running loop; cannot schedule hard exit here.
            pass

    def _hard_exit(self) -> None:
        if self._stop_event.is_set():
            logger.warning("Graceful shutdown timed out; forcing exit")
            os._exit(1)

    def _state_dict(self) -> dict:
        return {
            "allowed_ports": sorted(self.allowed_ports),
            "allowed_per_ip": {ip: sorted(ports) for ip, ports in sorted(self.allowed_per_ip.items())},
            "blocked_ports": sorted(self.blocked_ports),
        }

    def _save_state(self) -> None:
        """Persist runtime allow/block/deny state to disk."""
        try:
            os.makedirs(self.cfg.run_dir, exist_ok=True, mode=0o750)
            Path(self.cfg.state_path).write_text(
                json.dumps(self._state_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except Exception:
            logger.exception("Failed to save daemon state to %s", self.cfg.state_path)

    def _load_state(self) -> None:
        """Load runtime allow/block/deny state from disk if present."""
        path = Path(self.cfg.state_path)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.allowed_ports = set(int(p) for p in data.get("allowed_ports", []))
            self.allowed_per_ip = {
                ip: set(int(p) for p in ports)
                for ip, ports in data.get("allowed_per_ip", {}).items()
            }
            self.blocked_ports = set(int(p) for p in data.get("blocked_ports", []))
            logger.info("Restored daemon state from %s", path)
        except Exception:
            logger.exception("Failed to load daemon state from %s", path)

    async def stop(self) -> None:
        async with self._stop_lock:
            if self._cleanup_done.is_set():
                return
            self._stop_event.set()
            for task in getattr(self, "_tasks", []):
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning("Task did not cancel within timeout")
                except asyncio.CancelledError:
                    pass
            try:
                await asyncio.wait_for(self._stop_all_honeypots(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Honeypot shutdown timed out; continuing")
            if self._server is not None:
                self._server.close()
                try:
                    await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
            try:
                self._hit_log_fh.close()
            except Exception:
                pass
            self._save_state()
            self._remove_pid()
            # Reset the primary chain. In ip6tables-only mode this is the IPv6
            # chain and the iptables_chain name is still used for the target.
            primary_family = "ipv6" if self.cfg.firewall_backend == "ip6tables" else "ipv4"
            self._firewall.reset(self.cfg.iptables_chain, family=primary_family)
            # Always reset the IPv6 chain too, even if enable_ipv6 is currently
            # false, so stale rules from a previous IPv6-enabled run do not
            # remain. Use the dedicated IPv6 backend if we have one, otherwise
            # create it just for cleanup. In ip6tables-only mode the primary
            # backend already owns the IPv6 chain, so skip the duplicate reset.
            try:
                if self.cfg.firewall_backend != "ip6tables":
                    backend_ipv6 = self._firewall_ipv6 or get_backend(self.cfg, family="ipv6")
                    backend_ipv6.reset(self.cfg.ipv6_chain, family="ipv6")
            except Exception:
                logger.exception("IPv6 reset during stop failed")
            logger.info("TsunamiWall daemon stopped")
            self._cleanup_done.set()

    async def _discovery_loop(self) -> None:
        iterations = 0
        while not self._stop_event.is_set():
            try:
                await self._reconcile()
            except Exception:
                logger.exception("Discovery/reconcile failed")

            # Periodically rotate the hit log and enforce payload retention.
            iterations += 1
            if iterations % 10 == 0:
                try:
                    self._hit_log_fh.flush()
                    rotated = rotate_hit_log(
                        self.cfg.hit_log_path,
                        self.cfg.hit_log_max_bytes,
                        self.cfg.hit_log_max_backups,
                    )
                    if rotated is not None:
                        self._hit_log_fh.close()
                        self._hit_log_fh = self._open_hit_log()
                    # Run the potentially expensive payload scan off the event loop.
                    try:
                        await asyncio.to_thread(
                            cleanup_payloads,
                            self.cfg.payload_log_dir,
                            self.cfg.payload_log_max_bytes,
                        )
                    except Exception:
                        logger.exception("Payload retention cleanup failed")
                except Exception:
                    logger.exception("Log rotation failed")

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.cfg.discovery_interval)
            except asyncio.TimeoutError:
                pass

    async def _reconcile(self) -> None:
        """Re-scan sockets, update allowed set and honeypots, rewrite iptables."""
        # Discover real listening sockets. IPv6 must be included whenever the
        # daemon manages an IPv6 ruleset, otherwise IPv6-only services would be
        # omitted from the auto-allowed set in default (non-strict) mode.
        # The daemon currently mirrors discovered real-service ports across both
        # address families: a service listening on a port is allowed on IPv4 and
        # IPv6 regardless of which family it actually bound. This matches the
        # common dual-stack pattern and keeps the rulesets small and consistent.
        # Strict per-family allow lists can be built with discover_ports_by_family()
        # if a future configuration option requires them.
        ipv6_enabled = (
            self.cfg.enable_ipv6 or self.cfg.firewall_backend == "ip6tables"
        )
        real_ports = discover_ports(
            include_tcp=True, include_udp=True, include_ipv6=ipv6_enabled
        )

        # Ports that are restricted to specific source IPs should not also be
        # allowed globally just because something is listening on them.
        per_ip_ports = set().union(*self.allowed_per_ip.values()) if self.allowed_per_ip else set()

        blocked = self.blocked_ports

        if self.cfg.auto_block_listeners:
            # Strict default-deny: only ports the user explicitly allows are opened.
            # Real services are not automatically allowed; they must be added via `allow`.
            managed_allowed = self.allowed_ports | (real_ports & self.allowed_ports)
        else:
            # Normal allow-list behavior: any listening socket is treated as a real service,
            # except ports that are already restricted to specific source IPs.
            managed_allowed = self.allowed_ports | (real_ports - per_ip_ports)

        # A global block wins over auto-discovery and per-IP allows.
        managed_allowed -= blocked

        # Compute available honeypot ports. Blocked ports must never become honeypots.
        available = safe_ports(managed_allowed, self.cfg) - blocked

        # Start honeypots that are not running.
        to_start = available - set(self.honeypots.keys())
        for port in sorted(to_start)[: self.cfg.max_honeypots - len(self.honeypots)]:
            hp = HoneypotServer(port, self._log_hit, cfg=self.cfg, payload_callback=self._payload_callback)
            try:
                await hp.start()
            except OSError as exc:
                logger.warning("Could not bind honeypot on TCP/%d: %s", port, exc)
                continue
            if port < 1024:
                logger.warning(
                    "Honeypot bound to privileged port TCP/%d; ensure no real service uses this port",
                    port,
                )
            self.honeypots[port] = hp

        # Stop honeypots that are now real services or outside allowed range.
        to_stop = set(self.honeypots.keys()) - available
        for port in to_stop:
            await self.honeypots.pop(port).stop()

        # Rewrite iptables. Global blocks override per-IP allows.
        honeypot_ports = set(self.honeypots.keys())
        allowed_per_ip = {
            ip: ports - blocked
            for ip, ports in self.allowed_per_ip.items()
            if ports - blocked
        }

        # Primary ruleset. In normal mode this is IPv4; in ip6tables-only mode it
        # is IPv6 and IPv4 is not managed at all.
        primary_family = "ipv6" if self.cfg.firewall_backend == "ip6tables" else "ipv4"
        self._firewall.build_rules(
            self.cfg.iptables_chain,
            managed_allowed,
            honeypot_ports,
            trusted_ips=self.cfg.trusted_ips,
            allowed_per_ip=allowed_per_ip,
            blocked_ports=self.blocked_ports,
            log_rate_limit=self.cfg.log_rate_limit,
            log_rate_burst=self.cfg.log_rate_burst,
            family=primary_family,
        )

        # IPv6 chain mirrors IPv4 allow policy for real services and per-IP rules,
        # but honeypots currently bind IPv4 only (to avoid fd exhaustion), so we must
        # not open those ports on the IPv6 side.  IPv6 probes to those ports are
        # dropped and logged instead, which is the safe behaviour until IPv6
        # honeypot listeners are implemented.
        if self._firewall_ipv6 is not None:
            try:
                self._firewall_ipv6.build_rules(
                    self.cfg.ipv6_chain,
                    managed_allowed,
                    set(),  # no IPv6 honeypot listeners yet
                    trusted_ips=self.cfg.trusted_ips,
                    allowed_per_ip=allowed_per_ip,
                    blocked_ports=self.blocked_ports,
                    log_rate_limit=self.cfg.log_rate_limit,
                    log_rate_burst=self.cfg.log_rate_burst,
                    family="ipv6",
                )
            except Exception:
                logger.exception("IPv6 rule build failed")
                # During startup the daemon must not advertise success if an
                # enabled IPv6 ruleset could not be installed. Re-raise so
                # start() fails visibly and the operator knows IPv6 is
                # unprotected. On periodic reconciles we log and continue,
                # because a transient failure should not tear down working
                # IPv4 protection.
                if self._startup_phase:
                    raise

        family_note = "IPv4 only" if self.cfg.firewall_backend == "ip6tables" else "IPv4/IPv6"
        logger.info("Reconciled: allowed=%s honeypots=%d family=%s", sorted(managed_allowed), len(honeypot_ports), family_note)
        self._save_state()

    async def _stop_all_honeypots(self) -> None:
        for port in list(self.honeypots.keys()):
            await self.honeypots.pop(port).stop()

    # ---------------- CLI unix socket handling ----------------

    async def _unix_socket_server(self) -> None:
        try:
            os.remove(self.cfg.socket_path)
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=self.cfg.socket_path,
        )
        os.chmod(self.cfg.socket_path, 0o660)
        logger.info("CLI socket ready at %s", self.cfg.socket_path)
        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await reader.read(4096)
            if not data:
                return
            try:
                cmd = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                writer.write((json.dumps({"ok": False, "error": "invalid json"}) + "\n").encode("utf-8"))
                return
            response = await self._process_command(cmd)
            writer.write((json.dumps(response) + "\n").encode("utf-8"))
            await writer.drain()
        except Exception as exc:
            logger.exception("CLI handler error")
            writer.write((json.dumps({"ok": False, "error": str(exc)}) + "\n").encode("utf-8"))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_command(self, cmd: dict[str, Any]) -> dict[str, Any]:
        action = cmd.get("action")
        if action == "status":
            return {
                "ok": True,
                "config_path": self.config_path,
                "config": {
                    "honeypot_start": self.cfg.honeypot_start,
                    "honeypot_end": self.cfg.honeypot_end,
                    "max_honeypots": self.cfg.max_honeypots,
                    "discovery_interval": self.cfg.discovery_interval,
                    "iptables_chain": self.cfg.iptables_chain,
                    "log_dir": self.cfg.log_dir,
                    "run_dir": self.cfg.run_dir,
                    "payload_max_bytes": self.cfg.payload_max_bytes,
                    "payload_read_timeout": self.cfg.payload_read_timeout,
                    "payload_log_dir": self.cfg.payload_log_dir,
                    "hit_log_max_bytes": self.cfg.hit_log_max_bytes,
                    "hit_log_max_backups": self.cfg.hit_log_max_backups,
                    "payload_log_max_bytes": self.cfg.payload_log_max_bytes,
                    "log_rate_limit": self.cfg.log_rate_limit,
                    "log_rate_burst": self.cfg.log_rate_burst,
                    "enable_ipv6": self.cfg.enable_ipv6,
                    "firewall_backend": self.cfg.firewall_backend,
                    "pfctl_anchor": self.cfg.pfctl_anchor,
                    "auto_block_listeners": self.cfg.auto_block_listeners,
                    "trusted_ips": sorted(self.cfg.trusted_ips),
                },
                "allowed_ports": sorted(self.allowed_ports),
                "allowed_per_ip": {
                    ip: sorted(ports) for ip, ports in sorted(self.allowed_per_ip.items())
                },
                "blocked_ports": sorted(self.blocked_ports),
                "honeypots": sorted(self.honeypots.keys()),
                "honeypot_count": len(self.honeypots),
            }
        if action == "allow":
            port = int(cmd.get("port", 0))
            if not 1 <= port <= 65535:
                return {"ok": False, "error": "invalid port"}
            self.allowed_ports.add(port)
            await self._reconcile()
            return {"ok": True, "allowed_port": port}
        if action == "allow_many":
            ports = cmd.get("ports", [])
            bad = [p for p in ports if not 1 <= p <= 65535]
            if bad:
                return {"ok": False, "error": f"invalid ports: {bad}"}
            ip = cmd.get("ip")
            if ip:
                try:
                    ipaddress.ip_network(ip, strict=False)
                except ValueError as exc:
                    return {"ok": False, "error": f"invalid ip: {exc}"}
                self.allowed_per_ip.setdefault(ip, set()).update(ports)
                await self._reconcile()
                return {"ok": True, "allowed_per_ip": {ip: sorted(self.allowed_per_ip[ip])}}
            self.allowed_ports.update(ports)
            await self._reconcile()
            return {"ok": True, "allowed_ports": sorted(ports)}
        if action == "deny":
            port = int(cmd.get("port", 0))
            self.allowed_ports.discard(port)
            await self._reconcile()
            return {"ok": True, "denied_port": port}
        if action == "deny_many":
            ports = cmd.get("ports", [])
            ip = cmd.get("ip")
            if ip:
                if ip not in self.allowed_per_ip:
                    return {"ok": True, "denied_per_ip": {ip: []}}
                self.allowed_per_ip[ip].difference_update(ports)
                if not self.allowed_per_ip[ip]:
                    del self.allowed_per_ip[ip]
                await self._reconcile()
                remaining = sorted(self.allowed_per_ip.get(ip, []))
                return {"ok": True, "denied_per_ip": {ip: sorted(ports)}, "remaining_per_ip": {ip: remaining}}
            self.allowed_ports.difference_update(ports)
            # If a port is denied, it should no longer be blocked either.
            self.blocked_ports.difference_update(ports)
            await self._reconcile()
            return {"ok": True, "denied_ports": sorted(ports)}
        if action == "block_many":
            ports = cmd.get("ports", [])
            bad = [p for p in ports if not 1 <= p <= 65535]
            if bad:
                return {"ok": False, "error": f"invalid ports: {bad}"}
            self.blocked_ports.update(ports)
            # A blocked port cannot be simultaneously allowed globally.
            self.allowed_ports.difference_update(ports)
            await self._reconcile()
            return {"ok": True, "blocked_ports": sorted(ports)}
        if action == "unblock_many":
            ports = cmd.get("ports", [])
            self.blocked_ports.difference_update(ports)
            await self._reconcile()
            return {"ok": True, "unblocked_ports": sorted(ports)}
        if action == "stop":
            # Set the stop event; start() will run the cleanup and exit.
            self._stop_event.set()
            return {"ok": True, "message": "daemon stopping gracefully; state will be saved"}
        if action == "reset":
            self._stop_event.set()
            await self.stop()
            return {"ok": True, "message": "daemon stopped and rules flushed"}
        return {"ok": False, "error": "unknown action"}


def _raise_fd_limit(minimum: int) -> None:
    """Raise the soft file-descriptor limit to at least *minimum*."""
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = max(soft, minimum)
        if target > hard:
            target = hard
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            logger.info("Raised file-descriptor limit to %d", target)
    except Exception:
        logger.debug("Could not raise file-descriptor limit", exc_info=True)


def run_daemon(*, cfg_path: str | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if os.geteuid() != 0:
        logger.error("TsunamiWall daemon must run as root")
        sys.exit(1)

    # Raise the soft file-descriptor limit to at least max_honeypots + buffer.
    # This prevents Too many open files when binding many honeypots and then
    # running firewall subprocesses.
    from .config import load_config

    cfg = load_config(cfg_path)
    _raise_fd_limit(cfg.max_honeypots + 128)

    daemon = Daemon(cfg, config_path=cfg_path)
    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        asyncio.run(daemon.stop())
