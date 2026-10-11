"""Asyncio honeypot listener for unused high ports."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import Callable

logger = logging.getLogger("tsunamiwall.honeypot")


@dataclass(frozen=True)
class HitEvent:
    time: str
    src_ip: str
    src_port: int
    dst_port: int
    proto: str
    action: str = "honeypot_hit"


class HoneypotServer:
    """A single TCP honeypot on one port."""

    def __init__(self, port: int, log_hit: Callable[[HitEvent], None]):
        self.port = port
        self.log_hit = log_hit
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

        event = HitEvent(
            time=_iso_now(),
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto="tcp",
        )
        self.log_hit(event)

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
