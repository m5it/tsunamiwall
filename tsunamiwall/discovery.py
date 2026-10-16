"""Discover listening IPv4 TCP and UDP sockets on the host."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Listener:
    """A single listening socket."""

    proto: str  # "tcp" or "udp"
    port: int
    local_ip: str


def _parse_proc_net_line(line: str) -> tuple[str, int] | None:
    """Parse one line from /proc/net/tcp or /proc/net/udp.

    Format (space separated, values 0-indexed):
      sl  local_address rem_address st tx_queue:rx_queue ...
    """
    parts = line.split()
    if len(parts) < 4:
        return None
    # state is hex in field index 3.  0x0A = TCP_LISTEN
    try:
        state = int(parts[3], 16)
    except ValueError:
        return None
    # /proc/net/udp does not have a LISTEN state, so accept all UDP entries
    # and let the caller decide. For TCP we only want LISTEN (0x0A).
    return parts[1], state


def _hex_ip_port(addr_field: str) -> tuple[str, int] | None:
    """Return (ip, port) from 'hexip:hexport'."""
    try:
        ip_hex, port_hex = addr_field.rsplit(":", 1)
    except ValueError:
        return None
    try:
        port = int(port_hex, 16)
    except ValueError:
        return None
    try:
        ip_bytes = bytes.fromhex(ip_hex.zfill(8))
    except ValueError:
        return None
    ip = ".".join(str(b) for b in reversed(ip_bytes))
    return ip, port


def _read_proc_net(path: str, proto: str) -> Iterable[Listener]:
    """Yield listeners from a /proc/net/{tcp,udp} file."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        header = True
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            if header:
                header = False
                continue
            parsed = _parse_proc_net_line(line)
            if parsed is None:
                continue
            addr_field, state = parsed
            addr = _hex_ip_port(addr_field)
            if addr is None:
                continue
            ip, port = addr
            # Skip UDP non-listeners? /proc/net/udp lists all sockets.
            # We treat every UDP entry with a local port as a listener.
            if proto == "tcp" and state != 0x0A:
                continue
            yield Listener(proto=proto, port=port, local_ip=ip)


def discover_listeners(
    *, include_tcp: bool = True, include_udp: bool = True, include_ipv6: bool = False
) -> set[Listener]:
    """Return a set of listening sockets found in /proc/net.

    IPv4 is parsed directly from /proc/net/tcp and /proc/net/udp. IPv6
    discovery defaults to off because the kernel represents IPv6 addresses
    as little-endian 128-bit words; use psutil for reliable IPv6 parsing.
    """
    listeners: set[Listener] = set()
    if include_tcp:
        listeners.update(_read_proc_net("/proc/net/tcp", "tcp"))
    if include_udp:
        listeners.update(_read_proc_net("/proc/net/udp", "udp"))
    if include_ipv6:
        listeners.update(discover_with_psutil_ipv6())
    return listeners


def discover_ports(
    *, include_tcp: bool = True, include_udp: bool = True, include_ipv6: bool = False
) -> set[int]:
    """Return just the port numbers of listening sockets.

    Note: even when include_ipv6 is true, the returned set is only port
    numbers. The caller must decide whether to manage IPv4, IPv6, or both.
    """
    return {
        l.port
        for l in discover_listeners(
            include_tcp=include_tcp, include_udp=include_udp, include_ipv6=include_ipv6
        )
    }


def has_ipv6_listener(port: int) -> bool:
    """Return True if *port* has an IPv6 listening socket."""
    for listener in discover_listeners(include_tcp=True, include_udp=True, include_ipv6=True):
        if listener.port == port and ":" in listener.local_ip:
            return True
    return False


# Optional psutil-based discovery for environments where /proc/net parsing is
# insufficient or unavailable.
def discover_with_psutil() -> set[int]:
    """Return listening ports using psutil, if installed."""
    try:
        import psutil
    except ImportError:
        return set()
    ports: set[int] = set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN:
            if conn.laddr:
                ports.add(conn.laddr.port)
    return ports


def discover_with_psutil_ipv6() -> set[Listener]:
    """Return IPv6 listening sockets using psutil, if installed."""
    try:
        import psutil
    except ImportError:
        return set()
    listeners: set[Listener] = set()
    for conn in psutil.net_connections(kind="inet6"):
        if conn.status == psutil.CONN_LISTEN:
            if conn.laddr:
                listeners.add(Listener(proto=conn.type.name.lower(), port=conn.laddr.port, local_ip=conn.laddr.ip))
    return listeners
