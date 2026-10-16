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
from .discovery import discover_ports
from .honeypot import (
    HitEvent,
    HoneypotServer,
    default_payload_writer,
    jsonl_formatter,
)
from .ip6tables import build_rules as build_rules_ipv6, reset as reset_ipv6
from .iptables import build_rules, reset
from .rotation import cleanup_payloads, rotate_hit_log

logger = logging.getLogger("tsunamiwall.daemon")


class Daemon:
    """Main TsunamiWall daemon."""

    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or default_config()
        self.honeypots: dict[int, HoneypotServer] = {}
        self.allowed_ports: set[int] = set()
        self.allowed_per_ip: dict[str, set[int]] = {}
        self.blocked_ports: set[int] = set()
        self._stop_event = asyncio.Event()
        self._stop_lock = asyncio.Lock()
        self._cleanup_done = asyncio.Event()
        self._server: asyncio.Server | None = None
        self._hit_log_fh = self._open_hit_log()
        self._payload_callback = default_payload_writer(self.cfg)
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

    async def start(self) -> None:
        os.makedirs(self.cfg.run_dir, exist_ok=True, mode=0o750)
        self._ensure_single_instance()
        self._write_pid()

        # Initial discovery and firewall setup.
        await self._reconcile()

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
            reset(self.cfg.iptables_chain)
            if self.cfg.enable_ipv6:
                try:
                    reset_ipv6(self.cfg.ipv6_chain)
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
                    cleanup_payloads(self.cfg.payload_log_dir, self.cfg.payload_log_max_bytes)
                except Exception:
                    logger.exception("Log/payload rotation failed")

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.cfg.discovery_interval)
            except asyncio.TimeoutError:
                pass

    async def _reconcile(self) -> None:
        """Re-scan sockets, update allowed set and honeypots, rewrite iptables."""
        real_ports = discover_ports(include_tcp=True, include_udp=True)

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
        build_rules(
            self.cfg.iptables_chain,
            managed_allowed,
            honeypot_ports,
            trusted_ips=self.cfg.trusted_ips,
            allowed_per_ip=allowed_per_ip,
            blocked_ports=self.blocked_ports,
            log_rate_limit=self.cfg.log_rate_limit,
            log_rate_burst=self.cfg.log_rate_burst,
        )

        # IPv6 chain mirrors IPv4 policy when enabled.
        if self.cfg.enable_ipv6:
            try:
                build_rules_ipv6(
                    self.cfg.ipv6_chain,
                    managed_allowed,
                    honeypot_ports,
                    trusted_ips=self.cfg.trusted_ips,
                    allowed_per_ip=allowed_per_ip,
                    blocked_ports=self.blocked_ports,
                    log_rate_limit=self.cfg.log_rate_limit,
                    log_rate_burst=self.cfg.log_rate_burst,
                )
            except Exception:
                logger.exception("IPv6 rule build failed")

        logger.info("Reconciled: allowed=%s honeypots=%d", sorted(managed_allowed), len(honeypot_ports))
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


def run_daemon(*, cfg_path: str | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if os.geteuid() != 0:
        logger.error("TsunamiWall daemon must run as root")
        sys.exit(1)

    from .config import load_config

    cfg = load_config(cfg_path)
    daemon = Daemon(cfg)
    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        asyncio.run(daemon.stop())
