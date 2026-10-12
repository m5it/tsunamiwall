"""Asyncio daemon for TsunamiWall."""

from __future__ import annotations

import asyncio
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
from .iptables import build_rules, reset

logger = logging.getLogger("tsunamiwall.daemon")


class Daemon:
    """Main TsunamiWall daemon."""

    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or default_config()
        self.honeypots: dict[int, HoneypotServer] = {}
        self.allowed_ports: set[int] = set()
        self._stop_event = asyncio.Event()
        self._server: asyncio.Server | None = None
        self._hit_log_fh = self._open_hit_log()
        self._payload_callback = default_payload_writer(self.cfg)

    def _open_hit_log(self):
        os.makedirs(self.cfg.log_dir, exist_ok=True, mode=0o750)
        return open(self.cfg.hit_log_path, "a", encoding="utf-8", buffering=1)

    def _log_hit(self, event: HitEvent) -> None:
        line = jsonl_formatter(event)
        self._hit_log_fh.write(line + "\n")
        self._hit_log_fh.flush()
        logger.info("Honeypot hit: %s", line)

    async def start(self) -> None:
        os.makedirs(self.cfg.run_dir, exist_ok=True, mode=0o750)
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

    async def stop(self) -> None:
        self._stop_event.set()
        for task in getattr(self, "_tasks", []):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await self._stop_all_honeypots()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        self._hit_log_fh.close()
        self._remove_pid()
        reset(self.cfg.iptables_chain)
        logger.info("TsunamiWall daemon stopped")

    async def _discovery_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self._reconcile()
            except Exception:
                logger.exception("Discovery/reconcile failed")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.cfg.discovery_interval)
            except asyncio.TimeoutError:
                pass

    async def _reconcile(self) -> None:
        """Re-scan sockets, update allowed set and honeypots, rewrite iptables."""
        real_ports = discover_ports(include_tcp=True, include_udp=True)
        # Also honor any user-allowed ports that may not currently be listening.
        managed_allowed = self.allowed_ports | real_ports

        # Compute available honeypot ports.
        available = safe_ports(managed_allowed, self.cfg)

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

        # Rewrite iptables.
        honeypot_ports = set(self.honeypots.keys())
        build_rules(
            self.cfg.iptables_chain,
            managed_allowed,
            honeypot_ports,
            trusted_ips=self.cfg.trusted_ips,
        )
        logger.debug("Reconciled: allowed=%s honeypots=%d", sorted(managed_allowed), len(honeypot_ports))

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
                writer.write(self._error("invalid json").encode("utf-8"))
                return
            response = await self._process_command(cmd)
            writer.write((json.dumps(response) + "\n").encode("utf-8"))
            await writer.drain()
        except Exception as exc:
            logger.exception("CLI handler error")
            writer.write(self._error(str(exc)).encode("utf-8"))
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
                "honeypots": sorted(self.honeypots.keys()),
                "honeypot_count": len(self.honeypots),
            }
        if action == "allow":
            port = int(cmd.get("port", 0))
            if not 1 <= port <= 65535:
                return self._error("invalid port")
            self.allowed_ports.add(port)
            await self._reconcile()
            return {"ok": True, "allowed_port": port}
        if action == "allow_many":
            ports = cmd.get("ports", [])
            bad = [p for p in ports if not 1 <= p <= 65535]
            if bad:
                return self._error(f"invalid ports: {bad}")
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
            self.allowed_ports.difference_update(ports)
            await self._reconcile()
            return {"ok": True, "denied_ports": sorted(ports)}
        if action == "reset":
            await self.stop()
            return {"ok": True, "message": "daemon stopped and rules flushed"}
        return self._error("unknown action")

    @staticmethod
    def _error(message: str) -> str:
        return json.dumps({"ok": False, "error": message}) + "\n"


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
