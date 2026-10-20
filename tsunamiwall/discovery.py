
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Listener:
    """A single listening socket."""

    proto: str  # "tcp" or "udp"
    port: int
    local_ip: str


def _parse_proc_net_line(line: str) -> tuple[str, str, int] | None:
    """Parse one line from /proc/net/tcp or /proc/net/udp.

    Format (space separated, values 0-indexed):
      sl  local_address rem_address st tx_queue:rx_queue ...

    Returns (local_address, remote_address, state).  For UDP we use a zeroed
    remote address (00000000:0000) to identify a bound/listening socket; UDP
    entries with a non-zero remote address are connected UDP sockets and
    should not be treated as listeners.
    """
    parts = line.split()
    if len(parts) < 4:
        return None
    # state is hex in field index 3.  0x0A = TCP_LISTEN
    try:
        state = int(parts[3], 16)
    except ValueError:
        return None
    return parts[1], parts[2], state


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




def _read_proc_net(path: str, proto: str, family: str = "ipv4") -> Iterable[Listener]:
    """Yield listeners from a /proc/net/{tcp,udp}[6] file."""
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
            local_field, remote_field, state = parsed
            local_addr = _hex_ip_port(local_field)
            if local_addr is None:
                continue
            ip, port = local_addr
            if proto == "tcp":
                if state != 0x0A:
                    continue
            else:
                # /proc/net/udp lists every UDP socket. A bound/listening UDP
                # socket has no peer, so its remote address is 0.0.0.0:0.
                # Connected UDP sockets have a non-zero remote address and must
                # not be treated as listeners. IPv6 uses the same zero check.
                if remote_field != "00000000:0000":
                    continue
            yield Listener(proto=proto, port=port, local_ip=ip)


def _read_proc_net_ipv6(path: str, proto: str) -> Iterable[Listener]:
    """Yield IPv6 listeners from a /proc/net/{tcp6,udp6} file.

    /proc/net/tcp6/udp6 address fields are 128-bit IPv6 addresses followed by
    a port, formatted as 32 hex digits and a 4-hex port. The kernel stores the
    address as four host-order 32-bit words, so on little-endian hosts the bytes
    within each 32-bit word are reversed compared to network byte order:
      00000000000000000000000000000000:0050  ... :: port 80
      00000000000000000000000001000000:0050  ... ::1 port 80
    """
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
            local_field, remote_field, state = parsed
            try:
                addr_hex, port_hex = local_field.rsplit(":", 1)
            except ValueError:
                continue
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            try:
                addr_bytes = bytes.fromhex(addr_hex.zfill(32))
            except ValueError:
                continue
            # Reverse each 32-bit word to convert from the kernel's host-order
            # representation back to network byte order.
            addr_bytes = b"".join(
                addr_bytes[i : i + 4][::-1] for i in range(0, 16, 4)
            )
            ip = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i + 1]:02x}" for i in range(0, 16, 2))
            # Compress IPv6 per RFC 5952-ish: collapse longest run of zeros.
            ip = _compress_ipv6(ip)
            if proto == "tcp":
                if state != 0x0A:
                    continue
            else:
                if remote_field != "00000000000000000000000000000000:0000":
                    continue
            yield Listener(proto=proto, port=port, local_ip=ip)


def _compress_ipv6(ip: str) -> str:
    """Compress a fully expanded IPv6 address into its shortest textual form."""
    groups = [g.lstrip("0") or "0" for g in ip.split(":")]
    # Find longest run of "0" groups to collapse.
    best_start = best_len = cur_start = cur_len = 0
    for i, g in enumerate(groups):
        if g == "0":
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_len = 0
    if best_len <= 1:
        return ":".join(groups)
    prefix = ":".join(groups[:best_start])
    suffix = ":".join(groups[best_start + best_len:])
    return f"{prefix}::{suffix}"


def discover_listeners(
    *, include_tcp: bool = True, include_udp: bool = True, include_ipv6: bool = False
) -> set[Listener]:
    """Return a set of listening sockets found in /proc/net or via psutil.

    On Linux, IPv4 is parsed directly from /proc/net/tcp and /proc/net/udp.
    IPv6 is parsed from /proc/net/tcp6 and /proc/net/udp6 when include_ipv6 is
    true. On macOS (or when /proc/net is unavailable), psutil is used instead.
    """
    listeners: set[Listener] = set()
    proc_net_available = os.path.exists("/proc/net/tcp")

    if proc_net_available:
        if include_tcp:
            listeners.update(_read_proc_net("/proc/net/tcp", "tcp"))
            if include_ipv6:
                listeners.update(_read_proc_net_ipv6("/proc/net/tcp6", "tcp"))
        if include_udp:
            listeners.update(_read_proc_net("/proc/net/udp", "udp"))
            if include_ipv6:
                listeners.update(_read_proc_net_ipv6("/proc/net/udp6", "udp"))
    else:
        # macOS and other non-Linux platforms: rely on psutil.
        listeners.update(discover_with_psutil())

    if include_ipv6 and not proc_net_available:
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
def _is_psutil_listener(conn) -> bool:
    """Return True if a psutil connection represents a listening socket.

    TCP sockets must be in the LISTEN state. UDP sockets are connectionless,
    so psutil usually reports them as CONN_NONE; we treat any UDP socket with a
    local address as a bound/listening socket.
    """
    import psutil

    if not conn.laddr:
        return False
    if conn.type.name == "SOCK_STREAM":
        return conn.status == psutil.CONN_LISTEN
    return conn.status in (psutil.CONN_LISTEN, psutil.CONN_NONE)


def discover_with_psutil() -> set[Listener]:
    """Return listening IPv4 sockets using psutil, if installed."""
    try:
        import psutil
    except ImportError:
        return set()
    listeners: set[Listener] = set()
    for conn in psutil.net_connections(kind="inet"):
        if _is_psutil_listener(conn):
            proto = "tcp" if conn.type.name == "SOCK_STREAM" else "udp"
            listeners.add(
                Listener(
                    proto=proto,
                    port=conn.laddr.port,
                    local_ip=conn.laddr.ip,
                )
            )
    return listeners


def discover_with_psutil_ipv6() -> set[Listener]:
    """Return IPv6 listening sockets using psutil, if installed."""
    try:
        import psutil
    except ImportError:
        return set()
    listeners: set[Listener] = set()
    for conn in psutil.net_connections(kind="inet6"):
        if _is_psutil_listener(conn):
            proto = "tcp" if conn.type.name == "SOCK_STREAM" else "udp"
            listeners.add(Listener(proto=proto, port=conn.laddr.port, local_ip=conn.laddr.ip))
    return listeners


