"""Asyncio honeypot listener for unused high ports."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .config import Config

logger = logging.getLogger("tsunamiwall.honeypot")


@dataclass(frozen=True)
class HitEvent:
    time: str
    src_ip: str
    src_port: int
    dst_port: int
    proto: str
    country: str = "UNKNOWN"
    action: str = "honeypot_hit"


@dataclass
class PayloadSession:
    """Collected data from one honeypot connection."""

    start_time: str
    src_ip: str
    src_port: int
    dst_port: int
    country: str = "UNKNOWN"
    payload: bytes = field(default_factory=bytes)


class HoneypotServer:
    """A single TCP honeypot on one port."""

    def __init__(
        self,
        port: int,
        log_hit: Callable[[HitEvent], None],
        cfg: Config | None = None,
        payload_callback: Callable[[PayloadSession], None] | None = None,
    ):
        self.port = port
        self.log_hit = log_hit
        self.cfg = cfg
        self.payload_callback = payload_callback
        self.server: asyncio.Server | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle,
            host="0.0.0.0",
            port=self.port,
        )
        logger.info("Honeypot listening on TCP/%d", self.port)

    async def stop(self) -> None:
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()
        self.server = None
        logger.info("Honeypot stopped on TCP/%d", self.port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        sockname = writer.get_extra_info("sockname")
        src_ip, src_port = peer[0], peer[1]
        dst_port = sockname[1]
        now = _iso_now()

        # Optional payload capture.
        session: PayloadSession | None = None
        payload = b""
        if self.cfg is not None and self.cfg.payload_max_bytes > 0:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(self.cfg.payload_max_bytes),
                    timeout=self.cfg.payload_read_timeout,
                )
                payload = chunk
            except asyncio.TimeoutError:
                pass
            except Exception as exc:
                logger.debug("Payload read error from %s:%d: %s", src_ip, src_port, exc)

            if self.payload_callback is not None:
                session = PayloadSession(
                    start_time=now,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    country="UNKNOWN",
                    payload=payload,
                )

        event = HitEvent(
            time=now,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto="tcp",
        )
        self.log_hit(event)

        if session is not None and self.payload_callback is not None:
            # Country code is filled in by the daemon callback which has access to
            # the lookup helper. We pass the session here as soon as connection closes.
            try:
                self.payload_callback(session)
            except Exception:
                logger.exception("Payload callback failed for %s:%d", src_ip, src_port)

        # Silently close after accepting; no banner in v1.
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def jsonl_formatter(event: HitEvent) -> str:
    return json.dumps(asdict(event), separators=(",", ":"))


def default_payload_writer(cfg: Config) -> Callable[[PayloadSession], None]:
    """Return a callback that writes payload data to by-country/by-ip files."""
    from .geoip import country_code, sanitize_ip

    base_dir = Path(cfg.payload_log_dir)

    def _write(session: PayloadSession) -> None:
        cc = country_code(session.src_ip)
        session.country = cc
        safe_ip = sanitize_ip(session.src_ip)
        ip_dir = base_dir / cc / safe_ip
        ip_dir.mkdir(parents=True, exist_ok=True, mode=0o750)

        # Use timestamp to avoid overwriting previous sessions from the same IP.
        filename = f"{session.start_time.replace(':', '-')}_{session.dst_port}.bin"
        payload_path = ip_dir / filename
        payload_path.write_bytes(session.payload)

        # Also append a small metadata line so you can list sessions easily.
        meta_path = ip_dir / "sessions.logl"
        meta = json.dumps(
            {
                "time": session.start_time,
                "src_ip": session.src_ip,
                "src_port": session.src_port,
                "dst_port": session.dst_port,
                "country": cc,
                "payload_bytes": len(session.payload),
                "payload_file": str(payload_path),
            },
            separators=(",", ":"),
        )
        with open(meta_path, "a", encoding="utf-8", buffering=1) as fh:
            fh.write(meta + "\n")

    return _write
